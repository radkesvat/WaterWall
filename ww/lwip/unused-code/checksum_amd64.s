# A version of checksum_amd64_go.s , re-written from go plan9 to AT&T

.section .rodata
.align 16
xmmLoadMasks:
    .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff
    .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
    .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    .byte 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    .byte 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff

.text

# uint16_t checksumAVX2(uint8_t *b, size_t len, uint16_t initial)
# Requires: AVX, AVX2, BMI2
.globl checksumAVX2
checksumAVX2:
    pushq   %rbx               # Save callee-saved register
    movzwl  %dx, %eax           # initial -> %ax, zero extend
    xchgb   %ah, %al            # swap bytes
    movq    %rdi, %rdx          # b -> %rdx
    movq    %rsi, %rbx          # len -> %rbx

    # handle odd length buffers; they are difficult to handle in general
    testq   $0x00000001, %rbx
    jz      lengthIsEven
    movzbq  -1(%rdx,%rbx,1), %rcx
    decq    %rbx
    addq    %rcx, %rax

lengthIsEven:
    # handle tiny buffers (<=31 bytes) specially
    cmpq    $0x1f, %rbx
    jg      bufferIsNotTiny
    xorq    %rcx, %rcx
    xorq    %rsi, %rsi
    xorq    %rdi, %rdi

    # shift twice to start because length is guaranteed to be even
    # n = n >> 2; CF = originalN & 2
    shrq    $0x02, %rbx
    jnc     handleTiny4

    # tmp2 = binary.LittleEndian.Uint16(buf[:2]); buf = buf[2:]
    movzwq  (%rdx), %rcx
    addq    $0x02, %rdx

handleTiny4:
    # n = n >> 1; CF = originalN & 4
    shrq    $0x01, %rbx
    jnc     handleTiny8

    # tmp4 = binary.LittleEndian.Uint32(buf[:4]); buf = buf[4:]
    movl    (%rdx), %esi
    addq    $0x04, %rdx

handleTiny8:
    # n = n >> 1; CF = originalN & 8
    shrq    $0x01, %rbx
    jnc     handleTiny16

    # tmp8 = binary.LittleEndian.Uint64(buf[:8]); buf = buf[8:]
    movq    (%rdx), %rdi
    addq    $0x08, %rdx

handleTiny16:
    # n = n >> 1; CF = originalN & 16
    # n == 0 now, otherwise we would have branched after comparing with tinyBufferSize
    shrq    $0x01, %rbx
    jnc     handleTinyFinish
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax

handleTinyFinish:
    # CF should be included from the previous add, so we use ADCQ.
    # If we arrived via the JNC above, then CF=0 due to the branch condition,
    # so ADCQ will still produce the correct result.
    adcq    %rcx, %rax
    adcq    %rsi, %rax
    adcq    %rdi, %rax
    jmp     foldAndReturn

bufferIsNotTiny:
    # skip all SIMD for small buffers
    cmpq    $0x00000100, %rbx
    jge     startSIMD

    # Accumulate carries in this register. It is never expected to overflow.
    xorq    %rsi, %rsi

    # We will perform an overlapped read for buffers with length not a multiple of 8.
    # Overlapped in this context means some memory will be read twice, but a shift will
    # eliminate the duplicated data. This extra read is performed at the end of the buffer to
    # preserve any alignment that may exist for the start of the buffer.
    movq    %rbx, %rcx
    shrq    $0x03, %rbx
    andq    $0x07, %rcx
    jz      handleRemaining8
    leaq    (%rdx,%rbx,8), %rdi
    movq    -8(%rdi,%rcx,1), %rdi

    # Shift out the duplicated data: overlapRead = overlapRead >> (64 - leftoverBytes*8)
    shlq    $0x03, %rcx
    negq    %rcx
    addq    $0x40, %rcx
    shrq    %cl, %rdi
    addq    %rdi, %rax
    adcq    $0x00, %rsi

handleRemaining8:
    shrq    $0x01, %rbx
    jnc     handleRemaining16
    addq    (%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x08, %rdx

handleRemaining16:
    shrq    $0x01, %rbx
    jnc     handleRemaining32
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x10, %rdx

handleRemaining32:
    shrq    $0x01, %rbx
    jnc     handleRemaining64
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax
    adcq    16(%rdx), %rax
    adcq    24(%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x20, %rdx

handleRemaining64:
    shrq    $0x01, %rbx
    jnc     handleRemaining128
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax
    adcq    16(%rdx), %rax
    adcq    24(%rdx), %rax
    adcq    32(%rdx), %rax
    adcq    40(%rdx), %rax
    adcq    48(%rdx), %rax
    adcq    56(%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x40, %rdx

handleRemaining128:
    shrq    $0x01, %rbx
    jnc     handleRemainingComplete
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax
    adcq    16(%rdx), %rax
    adcq    24(%rdx), %rax
    adcq    32(%rdx), %rax
    adcq    40(%rdx), %rax
    adcq    48(%rdx), %rax
    adcq    56(%rdx), %rax
    adcq    64(%rdx), %rax
    adcq    72(%rdx), %rax
    adcq    80(%rdx), %rax
    adcq    88(%rdx), %rax
    adcq    96(%rdx), %rax
    adcq    104(%rdx), %rax
    adcq    112(%rdx), %rax
    adcq    120(%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x80, %rdx

handleRemainingComplete:
    addq    %rsi, %rax
    jmp     foldAndReturn

startSIMD:
    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    movq    %rbx, %rcx

    # Update number of bytes remaining after the loop completes
    andq    $0xff, %rbx

    # Number of 256 byte iterations
    shrq    $0x08, %rcx
    jz      smallLoop

bigLoop:
    vpmovzxwd   (%rdx), %ymm4
    vpaddd      %ymm4, %ymm0, %ymm0
    vpmovzxwd   16(%rdx), %ymm4
    vpaddd      %ymm4, %ymm1, %ymm1
    vpmovzxwd   32(%rdx), %ymm4
    vpaddd      %ymm4, %ymm2, %ymm2
    vpmovzxwd   48(%rdx), %ymm4
    vpaddd      %ymm4, %ymm3, %ymm3
    vpmovzxwd   64(%rdx), %ymm4
    vpaddd      %ymm4, %ymm0, %ymm0
    vpmovzxwd   80(%rdx), %ymm4
    vpaddd      %ymm4, %ymm1, %ymm1
    vpmovzxwd   96(%rdx), %ymm4
    vpaddd      %ymm4, %ymm2, %ymm2
    vpmovzxwd   112(%rdx), %ymm4
    vpaddd      %ymm4, %ymm3, %ymm3
    vpmovzxwd   128(%rdx), %ymm4
    vpaddd      %ymm4, %ymm0, %ymm0
    vpmovzxwd   144(%rdx), %ymm4
    vpaddd      %ymm4, %ymm1, %ymm1
    vpmovzxwd   160(%rdx), %ymm4
    vpaddd      %ymm4, %ymm2, %ymm2
    vpmovzxwd   176(%rdx), %ymm4
    vpaddd      %ymm4, %ymm3, %ymm3
    vpmovzxwd   192(%rdx), %ymm4
    vpaddd      %ymm4, %ymm0, %ymm0
    vpmovzxwd   208(%rdx), %ymm4
    vpaddd      %ymm4, %ymm1, %ymm1
    vpmovzxwd   224(%rdx), %ymm4
    vpaddd      %ymm4, %ymm2, %ymm2
    vpmovzxwd   240(%rdx), %ymm4
    vpaddd      %ymm4, %ymm3, %ymm3
    addq        $0x00000100, %rdx
    decq        %rcx
    jnz         bigLoop
    cmpq        $0x10, %rbx
    jl          doneSmallLoop

    # now read a single 16 byte unit of data at a time
smallLoop:
    vpmovzxwd   (%rdx), %ymm4
    vpaddd      %ymm4, %ymm0, %ymm0
    addq        $0x10, %rdx
    subq        $0x10, %rbx
    cmpq        $0x10, %rbx
    jge         smallLoop

doneSmallLoop:
    cmpq    $0x00, %rbx
    je      doneSIMD

    # There are between 1 and 15 bytes remaining. Perform an overlapped read.
    leaq        xmmLoadMasks(%rip), %rcx
    vmovdqu     -16(%rdx,%rbx,1), %xmm4
    vpand       -16(%rcx,%rbx,8), %xmm4, %xmm4
    vpmovzxwd   %xmm4, %ymm4
    vpaddd      %ymm4, %ymm0, %ymm0

doneSIMD:
    # Multi-chain loop is done, combine the accumulators
    vpaddd      %ymm1, %ymm0, %ymm0
    vpaddd      %ymm2, %ymm0, %ymm0
    vpaddd      %ymm3, %ymm0, %ymm0

    # extract the YMM into a pair of XMM and sum them
    vextracti128    $0x01, %ymm0, %xmm1
    vpaddd          %xmm0, %xmm1, %xmm0

    # extract the XMM into GP64
    vpextrq     $0x00, %xmm0, %rcx
    vpextrq     $0x01, %xmm0, %rdx

    # no more AVX code, clear upper registers to avoid SSE slowdowns
    vzeroupper
    addq        %rcx, %rax
    adcq        %rdx, %rax

foldAndReturn:
    # add CF and fold using BMI2 instruction
    rorxq       $0x20, %rax, %rcx
    adcl        %ecx, %eax
    rorxl       $0x10, %eax, %ecx
    adcw        %cx, %ax
    adcw        $0x00, %ax
    xchgb       %ah, %al
    popq        %rbx           # Restore callee-saved register
    ret

# uint16_t checksumSSE2(uint8_t *b, size_t len, uint16_t initial)
# Requires: SSE2
.globl checksumSSE2
checksumSSE2:
    pushq   %rbx               # Save callee-saved register
    movzwl  %dx, %eax           # initial -> %ax, zero extend
    xchgb   %ah, %al            # swap bytes
    movq    %rdi, %rdx          # b -> %rdx
    movq    %rsi, %rbx          # len -> %rbx

    # handle odd length buffers; they are difficult to handle in general
    testq   $0x00000001, %rbx
    jz      lengthIsEven_sse2
    movzbq  -1(%rdx,%rbx,1), %rcx
    decq    %rbx
    addq    %rcx, %rax

lengthIsEven_sse2:
    # handle tiny buffers (<=31 bytes) specially
    cmpq    $0x1f, %rbx
    jg      bufferIsNotTiny_sse2
    xorq    %rcx, %rcx
    xorq    %rsi, %rsi
    xorq    %rdi, %rdi

    # shift twice to start because length is guaranteed to be even
    # n = n >> 2; CF = originalN & 2
    shrq    $0x02, %rbx
    jnc     handleTiny4_sse2

    # tmp2 = binary.LittleEndian.Uint16(buf[:2]); buf = buf[2:]
    movzwq  (%rdx), %rcx
    addq    $0x02, %rdx

handleTiny4_sse2:
    # n = n >> 1; CF = originalN & 4
    shrq    $0x01, %rbx
    jnc     handleTiny8_sse2

    # tmp4 = binary.LittleEndian.Uint32(buf[:4]); buf = buf[4:]
    movl    (%rdx), %esi
    addq    $0x04, %rdx

handleTiny8_sse2:
    # n = n >> 1; CF = originalN & 8
    shrq    $0x01, %rbx
    jnc     handleTiny16_sse2

    # tmp8 = binary.LittleEndian.Uint64(buf[:8]); buf = buf[8:]
    movq    (%rdx), %rdi
    addq    $0x08, %rdx

handleTiny16_sse2:
    # n = n >> 1; CF = originalN & 16
    # n == 0 now, otherwise we would have branched after comparing with tinyBufferSize
    shrq    $0x01, %rbx
    jnc     handleTinyFinish_sse2
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax

handleTinyFinish_sse2:
    # CF should be included from the previous add, so we use ADCQ.
    # If we arrived via the JNC above, then CF=0 due to the branch condition,
    # so ADCQ will still produce the correct result.
    adcq    %rcx, %rax
    adcq    %rsi, %rax
    adcq    %rdi, %rax
    jmp     foldAndReturn_sse2

bufferIsNotTiny_sse2:
    # skip all SIMD for small buffers
    cmpq    $0x00000100, %rbx
    jge     startSIMD_sse2

    # Accumulate carries in this register. It is never expected to overflow.
    xorq    %rsi, %rsi

    # We will perform an overlapped read for buffers with length not a multiple of 8.
    # Overlapped in this context means some memory will be read twice, but a shift will
    # eliminate the duplicated data. This extra read is performed at the end of the buffer to
    # preserve any alignment that may exist for the start of the buffer.
    movq    %rbx, %rcx
    shrq    $0x03, %rbx
    andq    $0x07, %rcx
    jz      handleRemaining8_sse2
    leaq    (%rdx,%rbx,8), %rdi
    movq    -8(%rdi,%rcx,1), %rdi

    # Shift out the duplicated data: overlapRead = overlapRead >> (64 - leftoverBytes*8)
    shlq    $0x03, %rcx
    negq    %rcx
    addq    $0x40, %rcx
    shrq    %cl, %rdi
    addq    %rdi, %rax
    adcq    $0x00, %rsi

handleRemaining8_sse2:
    shrq    $0x01, %rbx
    jnc     handleRemaining16_sse2
    addq    (%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x08, %rdx

handleRemaining16_sse2:
    shrq    $0x01, %rbx
    jnc     handleRemaining32_sse2
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x10, %rdx

handleRemaining32_sse2:
    shrq    $0x01, %rbx
    jnc     handleRemaining64_sse2
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax
    adcq    16(%rdx), %rax
    adcq    24(%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x20, %rdx

handleRemaining64_sse2:
    shrq    $0x01, %rbx
    jnc     handleRemaining128_sse2
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax
    adcq    16(%rdx), %rax
    adcq    24(%rdx), %rax
    adcq    32(%rdx), %rax
    adcq    40(%rdx), %rax
    adcq    48(%rdx), %rax
    adcq    56(%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x40, %rdx

handleRemaining128_sse2:
    shrq    $0x01, %rbx
    jnc     handleRemainingComplete_sse2
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax
    adcq    16(%rdx), %rax
    adcq    24(%rdx), %rax
    adcq    32(%rdx), %rax
    adcq    40(%rdx), %rax
    adcq    48(%rdx), %rax
    adcq    56(%rdx), %rax
    adcq    64(%rdx), %rax
    adcq    72(%rdx), %rax
    adcq    80(%rdx), %rax
    adcq    88(%rdx), %rax
    adcq    96(%rdx), %rax
    adcq    104(%rdx), %rax
    adcq    112(%rdx), %rax
    adcq    120(%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x80, %rdx

handleRemainingComplete_sse2:
    addq    %rsi, %rax
    jmp     foldAndReturn_sse2

startSIMD_sse2:
    pxor    %xmm0, %xmm0
    pxor    %xmm1, %xmm1
    pxor    %xmm2, %xmm2
    pxor    %xmm3, %xmm3
    pxor    %xmm4, %xmm4
    movq    %rbx, %rcx

    # Update number of bytes remaining after the loop completes
    andq    $0xff, %rbx

    # Number of 256 byte iterations
    shrq    $0x08, %rcx
    jz      smallLoop_sse2

bigLoop_sse2:
    movdqu      (%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm0
    paddd       %xmm6, %xmm2
    movdqu      16(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm1
    paddd       %xmm6, %xmm3
    movdqu      32(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm2
    paddd       %xmm6, %xmm0
    movdqu      48(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm3
    paddd       %xmm6, %xmm1
    movdqu      64(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm0
    paddd       %xmm6, %xmm2
    movdqu      80(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm1
    paddd       %xmm6, %xmm3
    movdqu      96(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm2
    paddd       %xmm6, %xmm0
    movdqu      112(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm3
    paddd       %xmm6, %xmm1
    movdqu      128(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm0
    paddd       %xmm6, %xmm2
    movdqu      144(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm1
    paddd       %xmm6, %xmm3
    movdqu      160(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm2
    paddd       %xmm6, %xmm0
    movdqu      176(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm3
    paddd       %xmm6, %xmm1
    movdqu      192(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm0
    paddd       %xmm6, %xmm2
    movdqu      208(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm1
    paddd       %xmm6, %xmm3
    movdqu      224(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm2
    paddd       %xmm6, %xmm0
    movdqu      240(%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm3
    paddd       %xmm6, %xmm1
    addq        $0x00000100, %rdx
    decq        %rcx
    jnz         bigLoop_sse2
    cmpq        $0x10, %rbx
    jl          doneSmallLoop_sse2

    # now read a single 16 byte unit of data at a time
smallLoop_sse2:
    movdqu      (%rdx), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm0
    paddd       %xmm6, %xmm1
    addq        $0x10, %rdx
    subq        $0x10, %rbx
    cmpq        $0x10, %rbx
    jge         smallLoop_sse2

doneSmallLoop_sse2:
    cmpq    $0x00, %rbx
    je      doneSIMD_sse2

    # There are between 1 and 15 bytes remaining. Perform an overlapped read.
    leaq        xmmLoadMasks(%rip), %rcx
    movdqu      -16(%rdx,%rbx,1), %xmm5
    pand        -16(%rcx,%rbx,8), %xmm5
    movdqa      %xmm5, %xmm6
    punpckhwd   %xmm4, %xmm5
    punpcklwd   %xmm4, %xmm6
    paddd       %xmm5, %xmm0
    paddd       %xmm6, %xmm1

doneSIMD_sse2:
    # Multi-chain loop is done, combine the accumulators
    paddd       %xmm1, %xmm0
    paddd       %xmm2, %xmm0
    paddd       %xmm3, %xmm0

    # extract the XMM into GP64
    movq        %xmm0, %rcx
    psrldq      $0x08, %xmm0
    movq        %xmm0, %rdx
    addq        %rcx, %rax
    adcq        %rdx, %rax

foldAndReturn_sse2:
    # add CF and fold
    movl        %eax, %ecx
    adcq        $0x00, %rcx
    shrq        $0x20, %rax
    addq        %rcx, %rax
    movzwq      %ax, %rcx
    shrq        $0x10, %rax
    addq        %rcx, %rax
    movw        %ax, %cx
    shrq        $0x10, %rax
    addw        %cx, %ax
    adcw        $0x00, %ax
    xchgb       %ah, %al
    popq        %rbx           # Restore callee-saved register
    ret

# uint16_t checksumAMD64(uint8_t *b, size_t len, uint16_t initial)
.globl checksumAMD64
checksumAMD64:
    pushq   %rbx               # Save callee-saved register
    pushq   %r12               # Save additional callee-saved register
    movzwl  %dx, %eax           # initial -> %ax, zero extend
    xchgb   %ah, %al            # swap bytes
    movq    %rdi, %rdx          # b -> %rdx
    movq    %rsi, %rbx          # len -> %rbx

    # handle odd length buffers; they are difficult to handle in general
    testq   $0x00000001, %rbx
    jz      lengthIsEven_amd64
    movzbq  -1(%rdx,%rbx,1), %rcx
    decq    %rbx
    addq    %rcx, %rax

lengthIsEven_amd64:
    # handle tiny buffers (<=31 bytes) specially
    cmpq    $0x1f, %rbx
    jg      bufferIsNotTiny_amd64
    xorq    %rcx, %rcx
    xorq    %rsi, %rsi
    xorq    %rdi, %rdi

    # shift twice to start because length is guaranteed to be even
    # n = n >> 2; CF = originalN & 2
    shrq    $0x02, %rbx
    jnc     handleTiny4_amd64

    # tmp2 = binary.LittleEndian.Uint16(buf[:2]); buf = buf[2:]
    movzwq  (%rdx), %rcx
    addq    $0x02, %rdx

handleTiny4_amd64:
    # n = n >> 1; CF = originalN & 4
    shrq    $0x01, %rbx
    jnc     handleTiny8_amd64

    # tmp4 = binary.LittleEndian.Uint32(buf[:4]); buf = buf[4:]
    movl    (%rdx), %esi
    addq    $0x04, %rdx

handleTiny8_amd64:
    # n = n >> 1; CF = originalN & 8
    shrq    $0x01, %rbx
    jnc     handleTiny16_amd64

    # tmp8 = binary.LittleEndian.Uint64(buf[:8]); buf = buf[8:]
    movq    (%rdx), %rdi
    addq    $0x08, %rdx

handleTiny16_amd64:
    # n = n >> 1; CF = originalN & 16
    # n == 0 now, otherwise we would have branched after comparing with tinyBufferSize
    shrq    $0x01, %rbx
    jnc     handleTinyFinish_amd64
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax

handleTinyFinish_amd64:
    # CF should be included from the previous add, so we use ADCQ.
    # If we arrived via the JNC above, then CF=0 due to the branch condition,
    # so ADCQ will still produce the correct result.
    adcq    %rcx, %rax
    adcq    %rsi, %rax
    adcq    %rdi, %rax
    jmp     foldAndReturn_amd64

bufferIsNotTiny_amd64:
    # Number of 256 byte iterations into loop counter
    movq    %rbx, %rcx

    # Update number of bytes remaining after the loop completes
    andq    $0xff, %rbx
    shrq    $0x08, %rcx
    jz      startCleanup
    clc
    xorq    %rsi, %rsi
    xorq    %rdi, %rdi
    xorq    %r8, %r8
    xorq    %r9, %r9
    xorq    %r10, %r10
    xorq    %r11, %r11
    xorq    %r12, %r12

bigLoop_amd64:
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax
    adcq    16(%rdx), %rax
    adcq    24(%rdx), %rax
    adcq    $0x00, %rsi
    addq    32(%rdx), %rdi
    adcq    40(%rdx), %rdi
    adcq    48(%rdx), %rdi
    adcq    56(%rdx), %rdi
    adcq    $0x00, %r8
    addq    64(%rdx), %r9
    adcq    72(%rdx), %r9
    adcq    80(%rdx), %r9
    adcq    88(%rdx), %r9
    adcq    $0x00, %r10
    addq    96(%rdx), %r11
    adcq    104(%rdx), %r11
    adcq    112(%rdx), %r11
    adcq    120(%rdx), %r11
    adcq    $0x00, %r12
    addq    128(%rdx), %rax
    adcq    136(%rdx), %rax
    adcq    144(%rdx), %rax
    adcq    152(%rdx), %rax
    adcq    $0x00, %rsi
    addq    160(%rdx), %rdi
    adcq    168(%rdx), %rdi
    adcq    176(%rdx), %rdi
    adcq    184(%rdx), %rdi
    adcq    $0x00, %r8
    addq    192(%rdx), %r9
    adcq    200(%rdx), %r9
    adcq    208(%rdx), %r9
    adcq    216(%rdx), %r9
    adcq    $0x00, %r10
    addq    224(%rdx), %r11
    adcq    232(%rdx), %r11
    adcq    240(%rdx), %r11
    adcq    248(%rdx), %r11
    adcq    $0x00, %r12
    addq    $0x00000100, %rdx
    subq    $0x01, %rcx
    jnz     bigLoop_amd64
    addq    %rsi, %rax
    adcq    %rdi, %rax
    adcq    %r8, %rax
    adcq    %r9, %rax
    adcq    %r10, %rax
    adcq    %r11, %rax
    adcq    %r12, %rax

    # accumulate CF (twice, in case the first time overflows)
    adcq    $0x00, %rax
    adcq    $0x00, %rax

startCleanup:
    # Accumulate carries in this register. It is never expected to overflow.
    xorq    %rsi, %rsi

    # We will perform an overlapped read for buffers with length not a multiple of 8.
    # Overlapped in this context means some memory will be read twice, but a shift will
    # eliminate the duplicated data. This extra read is performed at the end of the buffer to
    # preserve any alignment that may exist for the start of the buffer.
    movq    %rbx, %rcx
    shrq    $0x03, %rbx
    andq    $0x07, %rcx
    jz      handleRemaining8_amd64
    leaq    (%rdx,%rbx,8), %rdi
    movq    -8(%rdi,%rcx,1), %rdi

    # Shift out the duplicated data: overlapRead = overlapRead >> (64 - leftoverBytes*8)
    shlq    $0x03, %rcx
    negq    %rcx
    addq    $0x40, %rcx
    shrq    %cl, %rdi
    addq    %rdi, %rax
    adcq    $0x00, %rsi

handleRemaining8_amd64:
    shrq    $0x01, %rbx
    jnc     handleRemaining16_amd64
    addq    (%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x08, %rdx

handleRemaining16_amd64:
    shrq    $0x01, %rbx
    jnc     handleRemaining32_amd64
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x10, %rdx

handleRemaining32_amd64:
    shrq    $0x01, %rbx
    jnc     handleRemaining64_amd64
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax
    adcq    16(%rdx), %rax
    adcq    24(%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x20, %rdx

handleRemaining64_amd64:
    shrq    $0x01, %rbx
    jnc     handleRemaining128_amd64
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax
    adcq    16(%rdx), %rax
    adcq    24(%rdx), %rax
    adcq    32(%rdx), %rax
    adcq    40(%rdx), %rax
    adcq    48(%rdx), %rax
    adcq    56(%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x40, %rdx

handleRemaining128_amd64:
    shrq    $0x01, %rbx
    jnc     handleRemainingComplete_amd64
    addq    (%rdx), %rax
    adcq    8(%rdx), %rax
    adcq    16(%rdx), %rax
    adcq    24(%rdx), %rax
    adcq    32(%rdx), %rax
    adcq    40(%rdx), %rax
    adcq    48(%rdx), %rax
    adcq    56(%rdx), %rax
    adcq    64(%rdx), %rax
    adcq    72(%rdx), %rax
    adcq    80(%rdx), %rax
    adcq    88(%rdx), %rax
    adcq    96(%rdx), %rax
    adcq    104(%rdx), %rax
    adcq    112(%rdx), %rax
    adcq    120(%rdx), %rax
    adcq    $0x00, %rsi
    addq    $0x80, %rdx

handleRemainingComplete_amd64:
    addq    %rsi, %rax

foldAndReturn_amd64:
    # fold 64-bit sum to 16 bits
    movq    %rax, %rcx
    shrq    $32, %rcx
    addq    %rcx, %rax
    adcq    $0x00, %rax
    movq    %rax, %rcx
    shrq    $16, %rcx
    addq    %rcx, %rax
    adcq    $0x00, %rax
    andq    $0xffff, %rax
    xchgb   %ah, %al
    popq    %r12               # Restore callee-saved registers
    popq    %rbx
    ret
