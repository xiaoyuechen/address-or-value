	.file	"a-b-i.c"
	.text
	.data
	.align 32
	.type	b, @object
	.size	b, 40
b:
	.quad	0
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.align 32
	.type	a, @object
	.size	a, 40
a:
	.quad	1
	.quad	3
	.quad	5
	.quad	7
	.quad	9
	.section	.rodata
	.align 8
	.type	size, @object
	.size	size, 8
size:
	.quad	5
.LC0:
	.string	"%zu\n"
	.text
	.globl	main
	.type	main, @function
main:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movl	%edi, -20(%rbp)
	movq	%rsi, -32(%rbp)
	movq	a(%rip), %rax
	addq	$666, %rax
	movq	%rax, %rsi
	leaq	.LC0(%rip), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	printf@PLT
	movq	$0, -8(%rbp)
	jmp	.L2
.L3:
	movq	-8(%rbp), %rax
	leaq	0(,%rax,8), %rdx
	leaq	b(%rip), %rax
	movq	(%rdx,%rax), %rax
	leaq	0(,%rax,8), %rdx
	leaq	a(%rip), %rax
	movq	(%rdx,%rax), %rax
	movq	%rax, %rsi
	leaq	.LC0(%rip), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	printf@PLT
	addq	$1, -8(%rbp)
.L2:
	movl	$5, %eax
	cmpq	%rax, -8(%rbp)
	jb	.L3
	movl	$0, %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	main, .-main
	.ident	"GCC: (GNU) 11.1.0"
	.section	.note.GNU-stack,"",@progbits
