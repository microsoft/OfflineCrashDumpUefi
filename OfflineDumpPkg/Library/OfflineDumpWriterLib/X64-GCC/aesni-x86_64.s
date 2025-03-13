// Adapted from openssl/crypto/aes/asm/aesni-x86_64.pl

.text

.type   _aesni_encrypt2,@function
.align  16
_aesni_encrypt2:
.cfi_startproc
        movups  (%rcx),%xmm0
        shll    $4,%eax
        movups  16(%rcx),%xmm1
        xorps   %xmm0,%xmm2
        xorps   %xmm0,%xmm3
        movups  32(%rcx),%xmm0
        leaq    32(%rcx,%rax,1),%rcx
        negq    %rax
        addq    $16,%rax

.Lenc_loop2:
.byte   102,15,56,220,209
.byte   102,15,56,220,217
        movups  (%rcx,%rax,1),%xmm1
        addq    $32,%rax
.byte   102,15,56,220,208
.byte   102,15,56,220,216
        movups  -16(%rcx,%rax,1),%xmm0
        jnz     .Lenc_loop2

.byte   102,15,56,220,209
.byte   102,15,56,220,217
.byte   102,15,56,221,208
.byte   102,15,56,221,216
        .byte   0xf3,0xc3
.cfi_endproc
.size   _aesni_encrypt2,.-_aesni_encrypt2

.type   _aesni_encrypt3,@function
.align  16
_aesni_encrypt3:
.cfi_startproc
        movups  (%rcx),%xmm0
        shll    $4,%eax
        movups  16(%rcx),%xmm1
        xorps   %xmm0,%xmm2
        xorps   %xmm0,%xmm3
        xorps   %xmm0,%xmm4
        movups  32(%rcx),%xmm0
        leaq    32(%rcx,%rax,1),%rcx
        negq    %rax
        addq    $16,%rax

.Lenc_loop3:
.byte   102,15,56,220,209
.byte   102,15,56,220,217
.byte   102,15,56,220,225
        movups  (%rcx,%rax,1),%xmm1
        addq    $32,%rax
.byte   102,15,56,220,208
.byte   102,15,56,220,216
.byte   102,15,56,220,224
        movups  -16(%rcx,%rax,1),%xmm0
        jnz     .Lenc_loop3

.byte   102,15,56,220,209
.byte   102,15,56,220,217
.byte   102,15,56,220,225
.byte   102,15,56,221,208
.byte   102,15,56,221,216
.byte   102,15,56,221,224
        .byte   0xf3,0xc3
.cfi_endproc
.size   _aesni_encrypt3,.-_aesni_encrypt3

.type   _aesni_encrypt4,@function
.align  16
_aesni_encrypt4:
.cfi_startproc
        movups  (%rcx),%xmm0
        shll    $4,%eax
        movups  16(%rcx),%xmm1
        xorps   %xmm0,%xmm2
        xorps   %xmm0,%xmm3
        xorps   %xmm0,%xmm4
        xorps   %xmm0,%xmm5
        movups  32(%rcx),%xmm0
        leaq    32(%rcx,%rax,1),%rcx
        negq    %rax
.byte   0x0f,0x1f,0x00
        addq    $16,%rax

.Lenc_loop4:
.byte   102,15,56,220,209
.byte   102,15,56,220,217
.byte   102,15,56,220,225
.byte   102,15,56,220,233
        movups  (%rcx,%rax,1),%xmm1
        addq    $32,%rax
.byte   102,15,56,220,208
.byte   102,15,56,220,216
.byte   102,15,56,220,224
.byte   102,15,56,220,232
        movups  -16(%rcx,%rax,1),%xmm0
        jnz     .Lenc_loop4

.byte   102,15,56,220,209
.byte   102,15,56,220,217
.byte   102,15,56,220,225
.byte   102,15,56,220,233
.byte   102,15,56,221,208
.byte   102,15,56,221,216
.byte   102,15,56,221,224
.byte   102,15,56,221,232
        .byte   0xf3,0xc3
.cfi_endproc
.size   _aesni_encrypt4,.-_aesni_encrypt4

.type   _aesni_encrypt6,@function
.align  16
_aesni_encrypt6:
.cfi_startproc
        movups  (%rcx),%xmm0
        shll    $4,%eax
        movups  16(%rcx),%xmm1
        xorps   %xmm0,%xmm2
        pxor    %xmm0,%xmm3
        pxor    %xmm0,%xmm4
.byte   102,15,56,220,209
        leaq    32(%rcx,%rax,1),%rcx
        negq    %rax
.byte   102,15,56,220,217
        pxor    %xmm0,%xmm5
        pxor    %xmm0,%xmm6
.byte   102,15,56,220,225
        pxor    %xmm0,%xmm7
        movups  (%rcx,%rax,1),%xmm0
        addq    $16,%rax
        jmp     .Lenc_loop6_enter
.align  16
.Lenc_loop6:
.byte   102,15,56,220,209
.byte   102,15,56,220,217
.byte   102,15,56,220,225
.Lenc_loop6_enter:
.byte   102,15,56,220,233
.byte   102,15,56,220,241
.byte   102,15,56,220,249
        movups  (%rcx,%rax,1),%xmm1
        addq    $32,%rax
.byte   102,15,56,220,208
.byte   102,15,56,220,216
.byte   102,15,56,220,224
.byte   102,15,56,220,232
.byte   102,15,56,220,240
.byte   102,15,56,220,248
        movups  -16(%rcx,%rax,1),%xmm0
        jnz     .Lenc_loop6

.byte   102,15,56,220,209
.byte   102,15,56,220,217
.byte   102,15,56,220,225
.byte   102,15,56,220,233
.byte   102,15,56,220,241
.byte   102,15,56,220,249
.byte   102,15,56,221,208
.byte   102,15,56,221,216
.byte   102,15,56,221,224
.byte   102,15,56,221,232
.byte   102,15,56,221,240
.byte   102,15,56,221,248
        .byte   0xf3,0xc3
.cfi_endproc
.size   _aesni_encrypt6,.-_aesni_encrypt6

.type   _aesni_encrypt8,@function
.align  16
_aesni_encrypt8:
.cfi_startproc
        movups  (%rcx),%xmm0
        shll    $4,%eax
        movups  16(%rcx),%xmm1
        xorps   %xmm0,%xmm2
        xorps   %xmm0,%xmm3
        pxor    %xmm0,%xmm4
        pxor    %xmm0,%xmm5
        pxor    %xmm0,%xmm6
        leaq    32(%rcx,%rax,1),%rcx
        negq    %rax
.byte   102,15,56,220,209
        pxor    %xmm0,%xmm7
        pxor    %xmm0,%xmm8
.byte   102,15,56,220,217
        pxor    %xmm0,%xmm9
        movups  (%rcx,%rax,1),%xmm0
        addq    $16,%rax
        jmp     .Lenc_loop8_inner
.align  16
.Lenc_loop8:
.byte   102,15,56,220,209
.byte   102,15,56,220,217
.Lenc_loop8_inner:
.byte   102,15,56,220,225
.byte   102,15,56,220,233
.byte   102,15,56,220,241
.byte   102,15,56,220,249
.byte   102,68,15,56,220,193
.byte   102,68,15,56,220,201
.Lenc_loop8_enter:
        movups  (%rcx,%rax,1),%xmm1
        addq    $32,%rax
.byte   102,15,56,220,208
.byte   102,15,56,220,216
.byte   102,15,56,220,224
.byte   102,15,56,220,232
.byte   102,15,56,220,240
.byte   102,15,56,220,248
.byte   102,68,15,56,220,192
.byte   102,68,15,56,220,200
        movups  -16(%rcx,%rax,1),%xmm0
        jnz     .Lenc_loop8

.byte   102,15,56,220,209
.byte   102,15,56,220,217
.byte   102,15,56,220,225
.byte   102,15,56,220,233
.byte   102,15,56,220,241
.byte   102,15,56,220,249
.byte   102,68,15,56,220,193
.byte   102,68,15,56,220,201
.byte   102,15,56,221,208
.byte   102,15,56,221,216
.byte   102,15,56,221,224
.byte   102,15,56,221,232
.byte   102,15,56,221,240
.byte   102,15,56,221,248
.byte   102,68,15,56,221,192
.byte   102,68,15,56,221,200
        .byte   0xf3,0xc3
.cfi_endproc
.size   _aesni_encrypt8,.-_aesni_encrypt8

.globl  OD_accelerated_aes_ecb_encrypt
.type   OD_accelerated_aes_ecb_encrypt,@function
.align  16
OD_accelerated_aes_ecb_encrypt:
.cfi_startproc
.byte   243,15,30,250
        andq    $-16,%rdx
        jz      .Lecb_ret

        movl    240(%rcx),%eax
        movups  (%rcx),%xmm0
        movq    %rcx,%r11
        movl    %eax,%r10d
        /* testl   %r8d,%r8d */
        /* jz      .Lecb_decrypt */

        cmpq    $0x80,%rdx
        jb      .Lecb_enc_tail

        movdqu  (%rdi),%xmm2
        movdqu  16(%rdi),%xmm3
        movdqu  32(%rdi),%xmm4
        movdqu  48(%rdi),%xmm5
        movdqu  64(%rdi),%xmm6
        movdqu  80(%rdi),%xmm7
        movdqu  96(%rdi),%xmm8
        movdqu  112(%rdi),%xmm9
        leaq    128(%rdi),%rdi
        subq    $0x80,%rdx
        jmp     .Lecb_enc_loop8_enter
.align  16
.Lecb_enc_loop8:
        movups  %xmm2,(%rsi)
        movq    %r11,%rcx
        movdqu  (%rdi),%xmm2
        movl    %r10d,%eax
        movups  %xmm3,16(%rsi)
        movdqu  16(%rdi),%xmm3
        movups  %xmm4,32(%rsi)
        movdqu  32(%rdi),%xmm4
        movups  %xmm5,48(%rsi)
        movdqu  48(%rdi),%xmm5
        movups  %xmm6,64(%rsi)
        movdqu  64(%rdi),%xmm6
        movups  %xmm7,80(%rsi)
        movdqu  80(%rdi),%xmm7
        movups  %xmm8,96(%rsi)
        movdqu  96(%rdi),%xmm8
        movups  %xmm9,112(%rsi)
        leaq    128(%rsi),%rsi
        movdqu  112(%rdi),%xmm9
        leaq    128(%rdi),%rdi
.Lecb_enc_loop8_enter:

        call    _aesni_encrypt8

        subq    $0x80,%rdx
        jnc     .Lecb_enc_loop8

        movups  %xmm2,(%rsi)
        movq    %r11,%rcx
        movups  %xmm3,16(%rsi)
        movl    %r10d,%eax
        movups  %xmm4,32(%rsi)
        movups  %xmm5,48(%rsi)
        movups  %xmm6,64(%rsi)
        movups  %xmm7,80(%rsi)
        movups  %xmm8,96(%rsi)
        movups  %xmm9,112(%rsi)
        leaq    128(%rsi),%rsi
        addq    $0x80,%rdx
        jz      .Lecb_ret

.Lecb_enc_tail:
        movups  (%rdi),%xmm2
        cmpq    $0x20,%rdx
        jb      .Lecb_enc_one
        movups  16(%rdi),%xmm3
        je      .Lecb_enc_two
        movups  32(%rdi),%xmm4
        cmpq    $0x40,%rdx
        jb      .Lecb_enc_three
        movups  48(%rdi),%xmm5
        je      .Lecb_enc_four
        movups  64(%rdi),%xmm6
        cmpq    $0x60,%rdx
        jb      .Lecb_enc_five
        movups  80(%rdi),%xmm7
        je      .Lecb_enc_six
        movdqu  96(%rdi),%xmm8
        xorps   %xmm9,%xmm9
        call    _aesni_encrypt8
        movups  %xmm2,(%rsi)
        movups  %xmm3,16(%rsi)
        movups  %xmm4,32(%rsi)
        movups  %xmm5,48(%rsi)
        movups  %xmm6,64(%rsi)
        movups  %xmm7,80(%rsi)
        movups  %xmm8,96(%rsi)
        jmp     .Lecb_ret
.align  16
.Lecb_enc_one:
        movups  (%rcx),%xmm0
        movups  16(%rcx),%xmm1
        leaq    32(%rcx),%rcx
        xorps   %xmm0,%xmm2
.Loop_enc1_3:
.byte   102,15,56,220,209
        decl    %eax
        movups  (%rcx),%xmm1
        leaq    16(%rcx),%rcx
        jnz     .Loop_enc1_3
.byte   102,15,56,221,209
        movups  %xmm2,(%rsi)
        jmp     .Lecb_ret
.align  16
.Lecb_enc_two:
        call    _aesni_encrypt2
        movups  %xmm2,(%rsi)
        movups  %xmm3,16(%rsi)
        jmp     .Lecb_ret
.align  16
.Lecb_enc_three:
        call    _aesni_encrypt3
        movups  %xmm2,(%rsi)
        movups  %xmm3,16(%rsi)
        movups  %xmm4,32(%rsi)
        jmp     .Lecb_ret
.align  16
.Lecb_enc_four:
        call    _aesni_encrypt4
        movups  %xmm2,(%rsi)
        movups  %xmm3,16(%rsi)
        movups  %xmm4,32(%rsi)
        movups  %xmm5,48(%rsi)
        jmp     .Lecb_ret
.align  16
.Lecb_enc_five:
        xorps   %xmm7,%xmm7
        call    _aesni_encrypt6
        movups  %xmm2,(%rsi)
        movups  %xmm3,16(%rsi)
        movups  %xmm4,32(%rsi)
        movups  %xmm5,48(%rsi)
        movups  %xmm6,64(%rsi)
        jmp     .Lecb_ret
.align  16
.Lecb_enc_six:
        call    _aesni_encrypt6
        movups  %xmm2,(%rsi)
        movups  %xmm3,16(%rsi)
        movups  %xmm4,32(%rsi)
        movups  %xmm5,48(%rsi)
        movups  %xmm6,64(%rsi)
        movups  %xmm7,80(%rsi)
        /* jmp     .Lecb_ret */

.Lecb_ret:
        xorps   %xmm0,%xmm0
        pxor    %xmm1,%xmm1
        .byte   0xf3,0xc3
.cfi_endproc
.size   OD_accelerated_aes_ecb_encrypt,.-OD_accelerated_aes_ecb_encrypt

.globl  OD_accelerated_aes_set_encrypt_key
.type   OD_accelerated_aes_set_encrypt_key,@function
.align  16
OD_accelerated_aes_set_encrypt_key:
__aesni_set_encrypt_key:
.cfi_startproc
.byte   0x48,0x83,0xEC,0x08
.cfi_adjust_cfa_offset  8
        movq    $-1,%rax
        testq   %rdi,%rdi
        jz      .Lenc_key_ret
        testq   %rdx,%rdx
        jz      .Lenc_key_ret

        /* movl    $268437504,%r10d */
        movups  (%rdi),%xmm0
        xorps   %xmm4,%xmm4
        /* andl    OPENSSL_ia32cap_P+4(%rip),%r10d */
        leaq    16(%rdx),%rax
        cmpl    $256,%esi
        je      .L14rounds
        cmpl    $192,%esi
        je      .L12rounds
        cmpl    $128,%esi
        jne     .Lbad_keybits

.L10rounds:
        movl    $9,%esi
        /* cmpl    $268435456,%r10d */
        /* je      .L10rounds_alt */

        movups  %xmm0,(%rdx)
.byte   102,15,58,223,200,1
        call    .Lkey_expansion_128_cold
.byte   102,15,58,223,200,2
        call    .Lkey_expansion_128
.byte   102,15,58,223,200,4
        call    .Lkey_expansion_128
.byte   102,15,58,223,200,8
        call    .Lkey_expansion_128
.byte   102,15,58,223,200,16
        call    .Lkey_expansion_128
.byte   102,15,58,223,200,32
        call    .Lkey_expansion_128
.byte   102,15,58,223,200,64
        call    .Lkey_expansion_128
.byte   102,15,58,223,200,128
        call    .Lkey_expansion_128
.byte   102,15,58,223,200,27
        call    .Lkey_expansion_128
.byte   102,15,58,223,200,54
        call    .Lkey_expansion_128
        movups  %xmm0,(%rax)
        movl    %esi,80(%rax)
        xorl    %eax,%eax
        jmp     .Lenc_key_ret

.align  16
.L12rounds:
        movq    16(%rdi),%xmm2
        movl    $11,%esi
        /* cmpl    $268435456,%r10d */
        /* je      .L12rounds_alt */

        movups  %xmm0,(%rdx)
.byte   102,15,58,223,202,1
        call    .Lkey_expansion_192a_cold
.byte   102,15,58,223,202,2
        call    .Lkey_expansion_192b
.byte   102,15,58,223,202,4
        call    .Lkey_expansion_192a
.byte   102,15,58,223,202,8
        call    .Lkey_expansion_192b
.byte   102,15,58,223,202,16
        call    .Lkey_expansion_192a
.byte   102,15,58,223,202,32
        call    .Lkey_expansion_192b
.byte   102,15,58,223,202,64
        call    .Lkey_expansion_192a
.byte   102,15,58,223,202,128
        call    .Lkey_expansion_192b
        movups  %xmm0,(%rax)
        movl    %esi,48(%rax)
        xorq    %rax,%rax
        jmp     .Lenc_key_ret

.align  16
.L14rounds:
        movups  16(%rdi),%xmm2
        movl    $13,%esi
        leaq    16(%rax),%rax
        /* cmpl    $268435456,%r10d */
        /* je      .L14rounds_alt */

        movups  %xmm0,(%rdx)
        movups  %xmm2,16(%rdx)
.byte   102,15,58,223,202,1
        call    .Lkey_expansion_256a_cold
.byte   102,15,58,223,200,1
        call    .Lkey_expansion_256b
.byte   102,15,58,223,202,2
        call    .Lkey_expansion_256a
.byte   102,15,58,223,200,2
        call    .Lkey_expansion_256b
.byte   102,15,58,223,202,4
        call    .Lkey_expansion_256a
.byte   102,15,58,223,200,4
        call    .Lkey_expansion_256b
.byte   102,15,58,223,202,8
        call    .Lkey_expansion_256a
.byte   102,15,58,223,200,8
        call    .Lkey_expansion_256b
.byte   102,15,58,223,202,16
        call    .Lkey_expansion_256a
.byte   102,15,58,223,200,16
        call    .Lkey_expansion_256b
.byte   102,15,58,223,202,32
        call    .Lkey_expansion_256a
.byte   102,15,58,223,200,32
        call    .Lkey_expansion_256b
.byte   102,15,58,223,202,64
        call    .Lkey_expansion_256a
        movups  %xmm0,(%rax)
        movl    %esi,16(%rax)
        xorq    %rax,%rax
        jmp     .Lenc_key_ret

.align  16
.Lbad_keybits:
        movq    $-2,%rax
.Lenc_key_ret:
        pxor    %xmm0,%xmm0
        pxor    %xmm1,%xmm1
        pxor    %xmm2,%xmm2
        pxor    %xmm3,%xmm3
        pxor    %xmm4,%xmm4
        pxor    %xmm5,%xmm5
        addq    $8,%rsp
.cfi_adjust_cfa_offset  -8
        .byte   0xf3,0xc3
.LSEH_end_set_encrypt_key:

.align  16
.Lkey_expansion_128:
        movups  %xmm0,(%rax)
        leaq    16(%rax),%rax
.Lkey_expansion_128_cold:
        shufps  $16,%xmm0,%xmm4
        xorps   %xmm4,%xmm0
        shufps  $140,%xmm0,%xmm4
        xorps   %xmm4,%xmm0
        shufps  $255,%xmm1,%xmm1
        xorps   %xmm1,%xmm0
        .byte   0xf3,0xc3

.align  16
.Lkey_expansion_192a:
        movups  %xmm0,(%rax)
        leaq    16(%rax),%rax
.Lkey_expansion_192a_cold:
        movaps  %xmm2,%xmm5
.Lkey_expansion_192b_warm:
        shufps  $16,%xmm0,%xmm4
        movdqa  %xmm2,%xmm3
        xorps   %xmm4,%xmm0
        shufps  $140,%xmm0,%xmm4
        pslldq  $4,%xmm3
        xorps   %xmm4,%xmm0
        pshufd  $85,%xmm1,%xmm1
        pxor    %xmm3,%xmm2
        pxor    %xmm1,%xmm0
        pshufd  $255,%xmm0,%xmm3
        pxor    %xmm3,%xmm2
        .byte   0xf3,0xc3

.align  16
.Lkey_expansion_192b:
        movaps  %xmm0,%xmm3
        shufps  $68,%xmm0,%xmm5
        movups  %xmm5,(%rax)
        shufps  $78,%xmm2,%xmm3
        movups  %xmm3,16(%rax)
        leaq    32(%rax),%rax
        jmp     .Lkey_expansion_192b_warm

.align  16
.Lkey_expansion_256a:
        movups  %xmm2,(%rax)
        leaq    16(%rax),%rax
.Lkey_expansion_256a_cold:
        shufps  $16,%xmm0,%xmm4
        xorps   %xmm4,%xmm0
        shufps  $140,%xmm0,%xmm4
        xorps   %xmm4,%xmm0
        shufps  $255,%xmm1,%xmm1
        xorps   %xmm1,%xmm0
        .byte   0xf3,0xc3

.align  16
.Lkey_expansion_256b:
        movups  %xmm0,(%rax)
        leaq    16(%rax),%rax

        shufps  $16,%xmm2,%xmm4
        xorps   %xmm4,%xmm2
        shufps  $140,%xmm2,%xmm4
        xorps   %xmm4,%xmm2
        shufps  $170,%xmm1,%xmm1
        xorps   %xmm1,%xmm2
        .byte   0xf3,0xc3
.cfi_endproc
.size   OD_accelerated_aes_set_encrypt_key,.-OD_accelerated_aes_set_encrypt_key
.size   __aesni_set_encrypt_key,.-__aesni_set_encrypt_key
