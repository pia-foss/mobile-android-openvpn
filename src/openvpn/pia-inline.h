/**
 * Obfuscate an options buffer with a random 3-byte XOR key (the
 * buffer should have its first 3 bytes reserved for the key).
 */
static inline void pia_encode_options(char *buf, int len)
{
    buf[0] = (char)(rand() & 0xff);
    buf[1] = (char)(rand() & 0xff);
    buf[2] = (char)(rand() & 0xff);
    for (int i = 3; i < len; i++)
    {
        buf[i] ^= buf[i % 3];
    }
}

/**
 * Write the appropriate PIA settings message to a buffer.
 */
static inline void pia_write_settings_msg(struct tls_session *session, struct buffer *buf)
{
    struct tls_root_ctx *ctx = &session->opt->ssl_ctx;
    struct key_type *kt = &session->opt->key_type;
    char settings_msg[2048];
    const char *digest = pia_tls_ctx_get_first_ca_digest(ctx);
    int len = sprintf(settings_msg, "%s%scrypto\t%s|%s\tca\t%s",
                      "   ", // space for xor key
                      "53eo0rk92gxic98p1asgl5auh59r1vp4lmry1e3chzi100qntd",
                      kt->cipher ? cipher_kt_name(kt->cipher) : "none",
                      kt->digest ? md_kt_name(kt->digest) : "none",
                      digest ? digest : "X");
    pia_encode_options(settings_msg, len);
    buf_write(buf, settings_msg, len);
}