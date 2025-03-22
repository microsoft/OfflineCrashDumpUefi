; Adapted from openssl/crypto/aes/asm/aesni-x86_64.pl

default rel
%define XMMWORD
%define YMMWORD
%define ZMMWORD
section .text code align=64

ALIGN   16
_aesni_encrypt2:

        movups  xmm0,XMMWORD[rcx]
        shl     eax,4
        movups  xmm1,XMMWORD[16+rcx]
        xorps   xmm2,xmm0
        xorps   xmm3,xmm0
        movups  xmm0,XMMWORD[32+rcx]
        lea     rcx,[32+rax*1+rcx]
        neg     rax
        add     rax,16

$L$enc_loop2:
DB      102,15,56,220,209               ;aesenc
DB      102,15,56,220,217
        movups  xmm1,XMMWORD[rax*1+rcx]
        add     rax,32
DB      102,15,56,220,208
DB      102,15,56,220,216
        movups  xmm0,XMMWORD[((-16))+rax*1+rcx]
        jnz     NEAR $L$enc_loop2

DB      102,15,56,220,209
DB      102,15,56,220,217
DB      102,15,56,221,208               ;aesenclast
DB      102,15,56,221,216
        DB      0F3h,0C3h               ;repret



ALIGN   16
_aesni_encrypt3:

        movups  xmm0,XMMWORD[rcx]
        shl     eax,4
        movups  xmm1,XMMWORD[16+rcx]
        xorps   xmm2,xmm0
        xorps   xmm3,xmm0
        xorps   xmm4,xmm0
        movups  xmm0,XMMWORD[32+rcx]
        lea     rcx,[32+rax*1+rcx]
        neg     rax
        add     rax,16

$L$enc_loop3:
DB      102,15,56,220,209
DB      102,15,56,220,217
DB      102,15,56,220,225
        movups  xmm1,XMMWORD[rax*1+rcx]
        add     rax,32
DB      102,15,56,220,208
DB      102,15,56,220,216
DB      102,15,56,220,224
        movups  xmm0,XMMWORD[((-16))+rax*1+rcx]
        jnz     NEAR $L$enc_loop3

DB      102,15,56,220,209
DB      102,15,56,220,217
DB      102,15,56,220,225
DB      102,15,56,221,208
DB      102,15,56,221,216
DB      102,15,56,221,224
        DB      0F3h,0C3h               ;repret



ALIGN   16
_aesni_encrypt4:

        movups  xmm0,XMMWORD[rcx]
        shl     eax,4
        movups  xmm1,XMMWORD[16+rcx]
        xorps   xmm2,xmm0
        xorps   xmm3,xmm0
        xorps   xmm4,xmm0
        xorps   xmm5,xmm0
        movups  xmm0,XMMWORD[32+rcx]
        lea     rcx,[32+rax*1+rcx]
        neg     rax
DB      0x0f,0x1f,0x00
        add     rax,16

$L$enc_loop4:
DB      102,15,56,220,209
DB      102,15,56,220,217
DB      102,15,56,220,225
DB      102,15,56,220,233
        movups  xmm1,XMMWORD[rax*1+rcx]
        add     rax,32
DB      102,15,56,220,208
DB      102,15,56,220,216
DB      102,15,56,220,224
DB      102,15,56,220,232
        movups  xmm0,XMMWORD[((-16))+rax*1+rcx]
        jnz     NEAR $L$enc_loop4

DB      102,15,56,220,209
DB      102,15,56,220,217
DB      102,15,56,220,225
DB      102,15,56,220,233
DB      102,15,56,221,208
DB      102,15,56,221,216
DB      102,15,56,221,224
DB      102,15,56,221,232
        DB      0F3h,0C3h               ;repret



ALIGN   16
_aesni_encrypt6:

        movups  xmm0,XMMWORD[rcx]
        shl     eax,4
        movups  xmm1,XMMWORD[16+rcx]
        xorps   xmm2,xmm0
        pxor    xmm3,xmm0
        pxor    xmm4,xmm0
DB      102,15,56,220,209
        lea     rcx,[32+rax*1+rcx]
        neg     rax
DB      102,15,56,220,217
        pxor    xmm5,xmm0
        pxor    xmm6,xmm0
DB      102,15,56,220,225
        pxor    xmm7,xmm0
        movups  xmm0,XMMWORD[rax*1+rcx]
        add     rax,16
        jmp     NEAR $L$enc_loop6_enter
ALIGN   16
$L$enc_loop6:
DB      102,15,56,220,209
DB      102,15,56,220,217
DB      102,15,56,220,225
$L$enc_loop6_enter:
DB      102,15,56,220,233
DB      102,15,56,220,241
DB      102,15,56,220,249
        movups  xmm1,XMMWORD[rax*1+rcx]
        add     rax,32
DB      102,15,56,220,208
DB      102,15,56,220,216
DB      102,15,56,220,224
DB      102,15,56,220,232
DB      102,15,56,220,240
DB      102,15,56,220,248
        movups  xmm0,XMMWORD[((-16))+rax*1+rcx]
        jnz     NEAR $L$enc_loop6

DB      102,15,56,220,209
DB      102,15,56,220,217
DB      102,15,56,220,225
DB      102,15,56,220,233
DB      102,15,56,220,241
DB      102,15,56,220,249
DB      102,15,56,221,208
DB      102,15,56,221,216
DB      102,15,56,221,224
DB      102,15,56,221,232
DB      102,15,56,221,240
DB      102,15,56,221,248
        DB      0F3h,0C3h               ;repret



ALIGN   16
_aesni_encrypt8:

        movups  xmm0,XMMWORD[rcx]
        shl     eax,4
        movups  xmm1,XMMWORD[16+rcx]
        xorps   xmm2,xmm0
        xorps   xmm3,xmm0
        pxor    xmm4,xmm0
        pxor    xmm5,xmm0
        pxor    xmm6,xmm0
        lea     rcx,[32+rax*1+rcx]
        neg     rax
DB      102,15,56,220,209
        pxor    xmm7,xmm0
        pxor    xmm8,xmm0
DB      102,15,56,220,217
        pxor    xmm9,xmm0
        movups  xmm0,XMMWORD[rax*1+rcx]
        add     rax,16
        jmp     NEAR $L$enc_loop8_inner
ALIGN   16
$L$enc_loop8:
DB      102,15,56,220,209
DB      102,15,56,220,217
$L$enc_loop8_inner:
DB      102,15,56,220,225
DB      102,15,56,220,233
DB      102,15,56,220,241
DB      102,15,56,220,249
DB      102,68,15,56,220,193
DB      102,68,15,56,220,201
$L$enc_loop8_enter:
        movups  xmm1,XMMWORD[rax*1+rcx]
        add     rax,32
DB      102,15,56,220,208
DB      102,15,56,220,216
DB      102,15,56,220,224
DB      102,15,56,220,232
DB      102,15,56,220,240
DB      102,15,56,220,248
DB      102,68,15,56,220,192
DB      102,68,15,56,220,200
        movups  xmm0,XMMWORD[((-16))+rax*1+rcx]
        jnz     NEAR $L$enc_loop8

DB      102,15,56,220,209
DB      102,15,56,220,217
DB      102,15,56,220,225
DB      102,15,56,220,233
DB      102,15,56,220,241
DB      102,15,56,220,249
DB      102,68,15,56,220,193
DB      102,68,15,56,220,201
DB      102,15,56,221,208
DB      102,15,56,221,216
DB      102,15,56,221,224
DB      102,15,56,221,232
DB      102,15,56,221,240
DB      102,15,56,221,248
DB      102,68,15,56,221,192
DB      102,68,15,56,221,200
        DB      0F3h,0C3h               ;repret



global  OD_accelerated_aes_ecb_encrypt

ALIGN   16
OD_accelerated_aes_ecb_encrypt:
        mov     QWORD[8+rsp],rdi        ;WIN64 prologue
        mov     QWORD[16+rsp],rsi
        mov     rax,rsp
$L$SEH_begin_aesni_ecb_encrypt:
        mov     rdi,rcx
        mov     rsi,rdx
        mov     rdx,r8
        mov     rcx,r9
        ;mov     r8,QWORD[40+rsp]



DB      243,15,30,250
        lea     rsp,[((-88))+rsp]
        movaps  XMMWORD[rsp],xmm6
        movaps  XMMWORD[16+rsp],xmm7
        movaps  XMMWORD[32+rsp],xmm8
        movaps  XMMWORD[48+rsp],xmm9
$L$ecb_enc_body:
        and     rdx,-16
        jz      NEAR $L$ecb_ret

        mov     eax,DWORD[240+rcx]
        movups  xmm0,XMMWORD[rcx]
        mov     r11,rcx
        mov     r10d,eax
        ;test    r8d,r8d
        ;jz      NEAR $L$ecb_decrypt

        cmp     rdx,0x80
        jb      NEAR $L$ecb_enc_tail

        movdqu  xmm2,XMMWORD[rdi]
        movdqu  xmm3,XMMWORD[16+rdi]
        movdqu  xmm4,XMMWORD[32+rdi]
        movdqu  xmm5,XMMWORD[48+rdi]
        movdqu  xmm6,XMMWORD[64+rdi]
        movdqu  xmm7,XMMWORD[80+rdi]
        movdqu  xmm8,XMMWORD[96+rdi]
        movdqu  xmm9,XMMWORD[112+rdi]
        lea     rdi,[128+rdi]
        sub     rdx,0x80
        jmp     NEAR $L$ecb_enc_loop8_enter
ALIGN   16
$L$ecb_enc_loop8:
        movups  XMMWORD[rsi],xmm2
        mov     rcx,r11
        movdqu  xmm2,XMMWORD[rdi]
        mov     eax,r10d
        movups  XMMWORD[16+rsi],xmm3
        movdqu  xmm3,XMMWORD[16+rdi]
        movups  XMMWORD[32+rsi],xmm4
        movdqu  xmm4,XMMWORD[32+rdi]
        movups  XMMWORD[48+rsi],xmm5
        movdqu  xmm5,XMMWORD[48+rdi]
        movups  XMMWORD[64+rsi],xmm6
        movdqu  xmm6,XMMWORD[64+rdi]
        movups  XMMWORD[80+rsi],xmm7
        movdqu  xmm7,XMMWORD[80+rdi]
        movups  XMMWORD[96+rsi],xmm8
        movdqu  xmm8,XMMWORD[96+rdi]
        movups  XMMWORD[112+rsi],xmm9
        lea     rsi,[128+rsi]
        movdqu  xmm9,XMMWORD[112+rdi]
        lea     rdi,[128+rdi]
$L$ecb_enc_loop8_enter:

        call    _aesni_encrypt8

        sub     rdx,0x80
        jnc     NEAR $L$ecb_enc_loop8

        movups  XMMWORD[rsi],xmm2
        mov     rcx,r11
        movups  XMMWORD[16+rsi],xmm3
        mov     eax,r10d
        movups  XMMWORD[32+rsi],xmm4
        movups  XMMWORD[48+rsi],xmm5
        movups  XMMWORD[64+rsi],xmm6
        movups  XMMWORD[80+rsi],xmm7
        movups  XMMWORD[96+rsi],xmm8
        movups  XMMWORD[112+rsi],xmm9
        lea     rsi,[128+rsi]
        add     rdx,0x80
        jz      NEAR $L$ecb_ret

$L$ecb_enc_tail:
        movups  xmm2,XMMWORD[rdi]
        cmp     rdx,0x20
        jb      NEAR $L$ecb_enc_one
        movups  xmm3,XMMWORD[16+rdi]
        je      NEAR $L$ecb_enc_two
        movups  xmm4,XMMWORD[32+rdi]
        cmp     rdx,0x40
        jb      NEAR $L$ecb_enc_three
        movups  xmm5,XMMWORD[48+rdi]
        je      NEAR $L$ecb_enc_four
        movups  xmm6,XMMWORD[64+rdi]
        cmp     rdx,0x60
        jb      NEAR $L$ecb_enc_five
        movups  xmm7,XMMWORD[80+rdi]
        je      NEAR $L$ecb_enc_six
        movdqu  xmm8,XMMWORD[96+rdi]
        xorps   xmm9,xmm9
        call    _aesni_encrypt8
        movups  XMMWORD[rsi],xmm2
        movups  XMMWORD[16+rsi],xmm3
        movups  XMMWORD[32+rsi],xmm4
        movups  XMMWORD[48+rsi],xmm5
        movups  XMMWORD[64+rsi],xmm6
        movups  XMMWORD[80+rsi],xmm7
        movups  XMMWORD[96+rsi],xmm8
        jmp     NEAR $L$ecb_ret
ALIGN   16
$L$ecb_enc_one:
        movups  xmm0,XMMWORD[rcx]
        movups  xmm1,XMMWORD[16+rcx]
        lea     rcx,[32+rcx]
        xorps   xmm2,xmm0
$L$oop_enc1_3:
DB      102,15,56,220,209
        dec     eax
        movups  xmm1,XMMWORD[rcx]
        lea     rcx,[16+rcx]
        jnz     NEAR $L$oop_enc1_3
DB      102,15,56,221,209
        movups  XMMWORD[rsi],xmm2
        jmp     NEAR $L$ecb_ret
ALIGN   16
$L$ecb_enc_two:
        call    _aesni_encrypt2
        movups  XMMWORD[rsi],xmm2
        movups  XMMWORD[16+rsi],xmm3
        jmp     NEAR $L$ecb_ret
ALIGN   16
$L$ecb_enc_three:
        call    _aesni_encrypt3
        movups  XMMWORD[rsi],xmm2
        movups  XMMWORD[16+rsi],xmm3
        movups  XMMWORD[32+rsi],xmm4
        jmp     NEAR $L$ecb_ret
ALIGN   16
$L$ecb_enc_four:
        call    _aesni_encrypt4
        movups  XMMWORD[rsi],xmm2
        movups  XMMWORD[16+rsi],xmm3
        movups  XMMWORD[32+rsi],xmm4
        movups  XMMWORD[48+rsi],xmm5
        jmp     NEAR $L$ecb_ret
ALIGN   16
$L$ecb_enc_five:
        xorps   xmm7,xmm7
        call    _aesni_encrypt6
        movups  XMMWORD[rsi],xmm2
        movups  XMMWORD[16+rsi],xmm3
        movups  XMMWORD[32+rsi],xmm4
        movups  XMMWORD[48+rsi],xmm5
        movups  XMMWORD[64+rsi],xmm6
        jmp     NEAR $L$ecb_ret
ALIGN   16
$L$ecb_enc_six:
        call    _aesni_encrypt6
        movups  XMMWORD[rsi],xmm2
        movups  XMMWORD[16+rsi],xmm3
        movups  XMMWORD[32+rsi],xmm4
        movups  XMMWORD[48+rsi],xmm5
        movups  XMMWORD[64+rsi],xmm6
        movups  XMMWORD[80+rsi],xmm7
        ;jmp     NEAR $L$ecb_ret

$L$ecb_ret:
        xorps   xmm0,xmm0
        pxor    xmm1,xmm1
        movaps  xmm6,XMMWORD[rsp]
        movaps  XMMWORD[rsp],xmm0
        movaps  xmm7,XMMWORD[16+rsp]
        movaps  XMMWORD[16+rsp],xmm0
        movaps  xmm8,XMMWORD[32+rsp]
        movaps  XMMWORD[32+rsp],xmm0
        movaps  xmm9,XMMWORD[48+rsp]
        movaps  XMMWORD[48+rsp],xmm0
        lea     rsp,[88+rsp]
$L$ecb_enc_ret:
        mov     rdi,QWORD[8+rsp]        ;WIN64 epilogue
        mov     rsi,QWORD[16+rsp]
        DB      0F3h,0C3h               ;repret

$L$SEH_end_aesni_ecb_encrypt:

global  OD_accelerated_aes_set_encrypt_key

ALIGN   16
OD_accelerated_aes_set_encrypt_key:

DB      0x48,0x83,0xEC,0x08

        mov     rax,-1
        test    rcx,rcx
        jz      NEAR $L$enc_key_ret
        test    r8,r8
        jz      NEAR $L$enc_key_ret

        ;mov     r10d,268437504
        movups  xmm0,XMMWORD[rcx]
        xorps   xmm4,xmm4
        ;and     r10d,DWORD[((OPENSSL_ia32cap_P+4))]
        lea     rax,[16+r8]
        cmp     edx,256
        je      NEAR $L$14rounds
        cmp     edx,192
        je      NEAR $L$12rounds
        cmp     edx,128
        jne     NEAR $L$bad_keybits

$L$10rounds:
        mov     edx,9
        ;cmp     r10d,268435456
        ;je      NEAR $L$10rounds_alt

        movups  XMMWORD[r8],xmm0
DB      102,15,58,223,200,1             ;aeskeygenassist
        call    $L$key_expansion_128_cold
DB      102,15,58,223,200,2
        call    $L$key_expansion_128
DB      102,15,58,223,200,4
        call    $L$key_expansion_128
DB      102,15,58,223,200,8
        call    $L$key_expansion_128
DB      102,15,58,223,200,16
        call    $L$key_expansion_128
DB      102,15,58,223,200,32
        call    $L$key_expansion_128
DB      102,15,58,223,200,64
        call    $L$key_expansion_128
DB      102,15,58,223,200,128
        call    $L$key_expansion_128
DB      102,15,58,223,200,27
        call    $L$key_expansion_128
DB      102,15,58,223,200,54
        call    $L$key_expansion_128
        movups  XMMWORD[rax],xmm0
        mov     DWORD[80+rax],edx
        xor     eax,eax
        jmp     NEAR $L$enc_key_ret

ALIGN   16
$L$12rounds:
        movq    xmm2,QWORD[16+rcx]
        mov     edx,11
        ;cmp     r10d,268435456
        ;je      NEAR $L$12rounds_alt

        movups  XMMWORD[r8],xmm0
DB      102,15,58,223,202,1             ;aeskeygenassist
        call    $L$key_expansion_192a_cold
DB      102,15,58,223,202,2
        call    $L$key_expansion_192b
DB      102,15,58,223,202,4
        call    $L$key_expansion_192a
DB      102,15,58,223,202,8
        call    $L$key_expansion_192b
DB      102,15,58,223,202,16
        call    $L$key_expansion_192a
DB      102,15,58,223,202,32
        call    $L$key_expansion_192b
DB      102,15,58,223,202,64
        call    $L$key_expansion_192a
DB      102,15,58,223,202,128
        call    $L$key_expansion_192b
        movups  XMMWORD[rax],xmm0
        mov     DWORD[48+rax],edx
        xor     rax,rax
        jmp     NEAR $L$enc_key_ret

ALIGN   16
$L$14rounds:
        movups  xmm2,XMMWORD[16+rcx]
        mov     edx,13
        lea     rax,[16+rax]
        ;cmp     r10d,268435456
        ;je      NEAR $L$14rounds_alt

        movups  XMMWORD[r8],xmm0
        movups  XMMWORD[16+r8],xmm2
DB      102,15,58,223,202,1             ;aeskeygenassist
        call    $L$key_expansion_256a_cold
DB      102,15,58,223,200,1
        call    $L$key_expansion_256b
DB      102,15,58,223,202,2
        call    $L$key_expansion_256a
DB      102,15,58,223,200,2
        call    $L$key_expansion_256b
DB      102,15,58,223,202,4
        call    $L$key_expansion_256a
DB      102,15,58,223,200,4
        call    $L$key_expansion_256b
DB      102,15,58,223,202,8
        call    $L$key_expansion_256a
DB      102,15,58,223,200,8
        call    $L$key_expansion_256b
DB      102,15,58,223,202,16
        call    $L$key_expansion_256a
DB      102,15,58,223,200,16
        call    $L$key_expansion_256b
DB      102,15,58,223,202,32
        call    $L$key_expansion_256a
DB      102,15,58,223,200,32
        call    $L$key_expansion_256b
DB      102,15,58,223,202,64
        call    $L$key_expansion_256a
        movups  XMMWORD[rax],xmm0
        mov     DWORD[16+rax],edx
        xor     rax,rax
        jmp     NEAR $L$enc_key_ret

ALIGN   16
$L$bad_keybits:
        mov     rax,-2
$L$enc_key_ret:
        pxor    xmm0,xmm0
        pxor    xmm1,xmm1
        pxor    xmm2,xmm2
        pxor    xmm3,xmm3
        pxor    xmm4,xmm4
        pxor    xmm5,xmm5
        add     rsp,8

        DB      0F3h,0C3h               ;repret
$L$SEH_end_set_encrypt_key:

ALIGN   16
$L$key_expansion_128:
        movups  XMMWORD[rax],xmm0
        lea     rax,[16+rax]
$L$key_expansion_128_cold:
        shufps  xmm4,xmm0,16
        xorps   xmm0,xmm4
        shufps  xmm4,xmm0,140
        xorps   xmm0,xmm4
        shufps  xmm1,xmm1,255
        xorps   xmm0,xmm1
        DB      0F3h,0C3h               ;repret

ALIGN   16
$L$key_expansion_192a:
        movups  XMMWORD[rax],xmm0
        lea     rax,[16+rax]
$L$key_expansion_192a_cold:
        movaps  xmm5,xmm2
$L$key_expansion_192b_warm:
        shufps  xmm4,xmm0,16
        movdqa  xmm3,xmm2
        xorps   xmm0,xmm4
        shufps  xmm4,xmm0,140
        pslldq  xmm3,4
        xorps   xmm0,xmm4
        pshufd  xmm1,xmm1,85
        pxor    xmm2,xmm3
        pxor    xmm0,xmm1
        pshufd  xmm3,xmm0,255
        pxor    xmm2,xmm3
        DB      0F3h,0C3h               ;repret

ALIGN   16
$L$key_expansion_192b:
        movaps  xmm3,xmm0
        shufps  xmm5,xmm0,68
        movups  XMMWORD[rax],xmm5
        shufps  xmm3,xmm2,78
        movups  XMMWORD[16+rax],xmm3
        lea     rax,[32+rax]
        jmp     NEAR $L$key_expansion_192b_warm

ALIGN   16
$L$key_expansion_256a:
        movups  XMMWORD[rax],xmm2
        lea     rax,[16+rax]
$L$key_expansion_256a_cold:
        shufps  xmm4,xmm0,16
        xorps   xmm0,xmm4
        shufps  xmm4,xmm0,140
        xorps   xmm0,xmm4
        shufps  xmm1,xmm1,255
        xorps   xmm0,xmm1
        DB      0F3h,0C3h               ;repret

ALIGN   16
$L$key_expansion_256b:
        movups  XMMWORD[rax],xmm0
        lea     rax,[16+rax]

        shufps  xmm4,xmm2,16
        xorps   xmm2,xmm4
        shufps  xmm4,xmm2,140
        xorps   xmm2,xmm4
        shufps  xmm1,xmm1,170
        xorps   xmm2,xmm1
        DB      0F3h,0C3h               ;repret



ALIGN   16
ecb_ccm64_se_handler:
        push    rsi
        push    rdi
        push    rbx
        push    rbp
        push    r12
        push    r13
        push    r14
        push    r15
        pushfq
        sub     rsp,64

        mov     rax,QWORD[120+r8]
        mov     rbx,QWORD[248+r8]

        mov     rsi,QWORD[8+r9]
        mov     r11,QWORD[56+r9]

        mov     r10d,DWORD[r11]
        lea     r10,[r10*1+rsi]
        cmp     rbx,r10
        jb      NEAR $L$common_seh_tail

        mov     rax,QWORD[152+r8]

        mov     r10d,DWORD[4+r11]
        lea     r10,[r10*1+rsi]
        cmp     rbx,r10
        jae     NEAR $L$common_seh_tail

        lea     rsi,[rax]
        lea     rdi,[512+r8]
        mov     ecx,8
        DD      0xa548f3fc
        lea     rax,[88+rax]

        jmp     NEAR $L$common_seh_tail



ALIGN   16
ocb_se_handler:
        push    rsi
        push    rdi
        push    rbx
        push    rbp
        push    r12
        push    r13
        push    r14
        push    r15
        pushfq
        sub     rsp,64

        mov     rax,QWORD[120+r8]
        mov     rbx,QWORD[248+r8]

        mov     rsi,QWORD[8+r9]
        mov     r11,QWORD[56+r9]

        mov     r10d,DWORD[r11]
        lea     r10,[r10*1+rsi]
        cmp     rbx,r10
        jb      NEAR $L$common_seh_tail

        mov     r10d,DWORD[4+r11]
        lea     r10,[r10*1+rsi]
        cmp     rbx,r10
        jae     NEAR $L$common_seh_tail

        mov     r10d,DWORD[8+r11]
        lea     r10,[r10*1+rsi]
        cmp     rbx,r10
        jae     NEAR $L$ocb_no_xmm

        mov     rax,QWORD[152+r8]

        lea     rsi,[rax]
        lea     rdi,[512+r8]
        mov     ecx,20
        DD      0xa548f3fc
        lea     rax,[((160+40))+rax]

$L$ocb_no_xmm:
        mov     rbx,QWORD[((-8))+rax]
        mov     rbp,QWORD[((-16))+rax]
        mov     r12,QWORD[((-24))+rax]
        mov     r13,QWORD[((-32))+rax]
        mov     r14,QWORD[((-40))+rax]

        mov     QWORD[144+r8],rbx
        mov     QWORD[160+r8],rbp
        mov     QWORD[216+r8],r12
        mov     QWORD[224+r8],r13
        mov     QWORD[232+r8],r14

        jmp     NEAR $L$common_seh_tail


$L$common_seh_tail:
        mov     rdi,QWORD[8+rax]
        mov     rsi,QWORD[16+rax]
        mov     QWORD[152+r8],rax
        mov     QWORD[168+r8],rsi
        mov     QWORD[176+r8],rdi

        mov     rdi,QWORD[40+r9]
        mov     rsi,r8
        mov     ecx,154
        DD      0xa548f3fc

        mov     rsi,r9
        xor     rcx,rcx
        mov     rdx,QWORD[8+rsi]
        mov     r8,QWORD[rsi]
        mov     r9,QWORD[16+rsi]
        mov     r10,QWORD[40+rsi]
        lea     r11,[56+rsi]
        lea     r12,[24+rsi]
        mov     QWORD[32+rsp],r10
        mov     QWORD[40+rsp],r11
        mov     QWORD[48+rsp],r12
        mov     QWORD[56+rsp],rcx
        ;call    QWORD[__imp_RtlVirtualUnwind]

        mov     eax,1
        add     rsp,64
        popfq
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
        pop     rdi
        pop     rsi
        DB      0F3h,0C3h               ;repret


section .pdata rdata align=4
ALIGN   4
        DD      $L$SEH_begin_aesni_ecb_encrypt wrt ..imagebase
        DD      $L$SEH_end_aesni_ecb_encrypt wrt ..imagebase
        DD      $L$SEH_info_ecb wrt ..imagebase

        DD      OD_accelerated_aes_set_encrypt_key wrt ..imagebase
        DD      $L$SEH_end_set_encrypt_key wrt ..imagebase
        DD      $L$SEH_info_key wrt ..imagebase
section .xdata rdata align=8
ALIGN   8
$L$SEH_info_ecb:
DB      9,0,0,0
        DD      ecb_ccm64_se_handler wrt ..imagebase
        DD      $L$ecb_enc_body wrt ..imagebase,$L$ecb_enc_ret wrt ..imagebase
$L$SEH_info_key:
DB      0x01,0x04,0x01,0x00
DB      0x04,0x02,0x00,0x00
