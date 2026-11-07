/*
 * crypt_threads_cmocka.c - the password hashes are right when computed
 * on several threads at once, as the crypt thread pool does.
 *
 * Each thread hashes its own password over and over and checks every
 * result against the one computed beforehand on a single thread.  A
 * mechanism that hands back a shared static buffer fails this: another
 * thread's hash shows up in it.
 */

#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <cmocka.h>

#include "ircd_crypt.h"
#include "ircd_crypt_bcrypt.h"
#include "ircd_crypt_native.h"
#include "ircd_crypt_smd5.h"

/* The mechanisms' register functions are not used here. */
int ircd_crypt_register_mech(crypt_mech_t *mechanism)
{
    (void)mechanism;
    return 0;
}

#define NTHREADS 4
#define ROUNDS 200

typedef const char *(*crypt_fn)(const char *, const char *);

struct job {
    crypt_fn fn;
    const char *salt;
    char key[16];
    char expect[128];
    int wrong;
};

static void *hash_loop(void *arg)
{
    struct job *job = arg;
    int i;

    for (i = 0; i < ROUNDS; i++) {
        const char *got = job->fn(job->key, job->salt);
        if (!got || strcmp(got, job->expect))
            job->wrong++;
    }
    return NULL;
}

static void run(crypt_fn fn, const char *salt)
{
    struct job jobs[NTHREADS];
    pthread_t th[NTHREADS];
    int i;

    for (i = 0; i < NTHREADS; i++) {
        const char *one;

        jobs[i].fn = fn;
        jobs[i].salt = salt;
        jobs[i].wrong = 0;
        snprintf(jobs[i].key, sizeof(jobs[i].key), "password%d", i);
        one = fn(jobs[i].key, salt);
        assert_non_null(one);
        assert_true(strlen(one) < sizeof(jobs[i].expect));
        strcpy(jobs[i].expect, one);
    }
    for (i = 0; i < NTHREADS; i++)
        assert_int_equal(pthread_create(&th[i], NULL, hash_loop, &jobs[i]), 0);
    for (i = 0; i < NTHREADS; i++) {
        pthread_join(th[i], NULL);
        assert_int_equal(jobs[i].wrong, 0);
    }
}

static void test_native_sha512(void **state)
{
    (void)state;
    run(ircd_crypt_native, "$6$rounds=1000$saltsaltsalt$");
}

static void test_smd5(void **state)
{
    (void)state;
    run(ircd_crypt_smd5, "saltsalt");
}

static void test_bcrypt(void **state)
{
    (void)state;
    run(ircd_crypt_bcrypt, "$2b$04$abcdefghijklmnopqrstuu");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_native_sha512),
        cmocka_unit_test(test_smd5),
        cmocka_unit_test(test_bcrypt),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
