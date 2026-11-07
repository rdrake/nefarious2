/* crule_cmocka.c - CMocka unit tests for connection rule parser
 *
 * Tests the connection rule grammar parser used for server link rules.
 * We inline the parser functions with CR_DEBUG and CR_CHKCONF defined
 * to avoid server dependencies, but prevent the built-in main().
 *
 * Grammar:
 *   rule:      orexpr END
 *   orexpr:    andexpr | andexpr || orexpr
 *   andexpr:   primary | primary && andexpr
 *   primary:   function | ! primary | ( orexpr )
 *   function:  word ( ) | word ( arglist )
 *   arglist:   word | word , arglist
 */

#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <cmocka.h>
/* Build the real parser from ../crule.c.  CR_CHKCONF is crule.c's own
 * standalone mode: it compiles crule_parse()/crule_free() and the parser
 * with malloc/free and no rule evaluation, so these tests exercise the
 * code the server runs instead of a copy of it. */
#define CR_CHKCONF
#include "../crule.c"

/* ========== Basic Parsing Tests ========== */

static void test_parse_empty_rule(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    /* Empty string should fail to parse */
    rule = crule_parse("");
    assert_null(rule);
}

static void test_parse_simple_function_no_args(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    /* directop() takes no arguments */
    rule = crule_parse("directop()");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_directop);
    assert_int_equal(rule->numargs, 0);
    crule_free(&rule);
    assert_null(rule);
}

static void test_parse_simple_function_one_arg(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    /* connected() takes one argument */
    rule = crule_parse("connected(*.example.com)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_connected);
    assert_int_equal(rule->numargs, 1);
    assert_string_equal((char*)rule->arg[0], "*.example.com");
    crule_free(&rule);
    assert_null(rule);
}

static void test_parse_simple_function_two_args(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    /* via() takes two arguments */
    rule = crule_parse("via(hub.*, *.leaf.net)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_via);
    assert_int_equal(rule->numargs, 2);
    assert_string_equal((char*)rule->arg[0], "hub.*");
    assert_string_equal((char*)rule->arg[1], "*.leaf.net");
    crule_free(&rule);
    assert_null(rule);
}

static void test_parse_directcon(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("directcon(irc.example.*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_directcon);
    assert_int_equal(rule->numargs, 1);
    assert_string_equal((char*)rule->arg[0], "irc.example.*");
    crule_free(&rule);
}

/* ========== NOT Operator Tests ========== */

static void test_parse_not_operator(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("!directop()");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__not);
    assert_int_equal(rule->numargs, 1);
    struct CRuleNode *child = (struct CRuleNode*)rule->arg[0];
    assert_non_null(child);
    assert_ptr_equal(child->funcptr, crule_directop);
    crule_free(&rule);
}

static void test_parse_double_not(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("!!directop()");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__not);
    struct CRuleNode *child = (struct CRuleNode*)rule->arg[0];
    assert_non_null(child);
    assert_ptr_equal(child->funcptr, crule__not);
    struct CRuleNode *grandchild = (struct CRuleNode*)child->arg[0];
    assert_non_null(grandchild);
    assert_ptr_equal(grandchild->funcptr, crule_directop);
    crule_free(&rule);
}

/* ========== AND Operator Tests ========== */

static void test_parse_and_operator(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("directop() && connected(*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__andor);
    assert_int_equal(rule->numargs, 3);
    assert_null(rule->arg[2]); /* NULL means AND */

    struct CRuleNode *left = (struct CRuleNode*)rule->arg[0];
    struct CRuleNode *right = (struct CRuleNode*)rule->arg[1];
    assert_non_null(left);
    assert_non_null(right);
    assert_ptr_equal(left->funcptr, crule_directop);
    assert_ptr_equal(right->funcptr, crule_connected);
    crule_free(&rule);
}

static void test_parse_chained_and(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("directop() && connected(*) && directcon(hub.*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__andor);
    crule_free(&rule);
}

/* ========== OR Operator Tests ========== */

static void test_parse_or_operator(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("directop() || connected(*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__andor);
    assert_int_equal(rule->numargs, 3);
    assert_non_null(rule->arg[2]); /* non-NULL means OR */

    struct CRuleNode *left = (struct CRuleNode*)rule->arg[0];
    struct CRuleNode *right = (struct CRuleNode*)rule->arg[1];
    assert_non_null(left);
    assert_non_null(right);
    assert_ptr_equal(left->funcptr, crule_directop);
    assert_ptr_equal(right->funcptr, crule_connected);
    crule_free(&rule);
}

static void test_parse_chained_or(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("directop() || connected(*) || directcon(hub.*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__andor);
    assert_non_null(rule->arg[2]); /* OR */
    crule_free(&rule);
}

/* ========== Precedence Tests ========== */

static void test_parse_and_or_precedence(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    /* AND has higher precedence than OR */
    rule = crule_parse("directop() || connected(*) && directcon(hub.*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__andor);
    assert_non_null(rule->arg[2]); /* OR at top level */
    crule_free(&rule);
}

static void test_parse_parentheses_override(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    /* Parentheses override normal precedence */
    rule = crule_parse("(directop() || connected(*)) && directcon(hub.*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__andor);
    assert_null(rule->arg[2]); /* AND at top level */

    struct CRuleNode *left = (struct CRuleNode*)rule->arg[0];
    assert_non_null(left);
    assert_ptr_equal(left->funcptr, crule__andor);
    assert_non_null(left->arg[2]); /* OR */
    crule_free(&rule);
}

static void test_parse_nested_parentheses(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("((directop()))");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_directop);
    crule_free(&rule);
}

/* ========== Error Handling Tests ========== */

static void test_parse_unknown_function(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("unknownfunc()");
    assert_null(rule);
}

static void test_parse_wrong_arg_count(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    /* directop takes 0 args */
    rule = crule_parse("directop(extra)");
    assert_null(rule);

    /* connected takes 1 arg */
    rule = crule_parse("connected()");
    assert_null(rule);

    /* via takes 2 args */
    rule = crule_parse("via(only.one)");
    assert_null(rule);
}

static void test_parse_unclosed_paren(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("(directop()");
    assert_null(rule);

    rule = crule_parse("directop(");
    assert_null(rule);
}

static void test_parse_unexpected_token(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("directop())");
    assert_null(rule);

    rule = crule_parse("directop() &&");
    assert_null(rule);

    rule = crule_parse("directop() ||");
    assert_null(rule);
}

static void test_parse_invalid_characters(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("@invalid");
    assert_null(rule);

    /* Single & is invalid */
    rule = crule_parse("directop() & connected(*)");
    assert_null(rule);

    /* Single | is invalid */
    rule = crule_parse("directop() | connected(*)");
    assert_null(rule);
}

/* ========== Whitespace Handling Tests ========== */

static void test_parse_extra_whitespace(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("  directop(  )  ");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_directop);
    crule_free(&rule);

    rule = crule_parse("directop()  &&  connected(*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__andor);
    crule_free(&rule);
}

static void test_parse_tabs(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("\tdirectop()\t&&\tconnected(*)\t");
    assert_non_null(rule);
    crule_free(&rule);
}

/* ========== Colon Terminator Tests ========== */

static void test_parse_colon_terminator(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("directop():extra stuff ignored");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_directop);
    crule_free(&rule);
}

/* ========== Wildcard Pattern Tests ========== */

static void test_parse_wildcard_patterns(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("connected(*.net)");
    assert_non_null(rule);
    assert_string_equal((char*)rule->arg[0], "*.net");
    crule_free(&rule);

    rule = crule_parse("connected(irc?.example.com)");
    assert_non_null(rule);
    assert_string_equal((char*)rule->arg[0], "irc?.example.com");
    crule_free(&rule);

    /* Use separate string to avoid trigraph warning */
    rule = crule_parse("connected(irc*.example.net)");
    assert_non_null(rule);
    assert_string_equal((char*)rule->arg[0], "irc*.example.net");
    crule_free(&rule);
}

static void test_parse_hostname_patterns(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("connected(irc.server.example.com)");
    assert_non_null(rule);
    assert_string_equal((char*)rule->arg[0], "irc.server.example.com");
    crule_free(&rule);

    rule = crule_parse("connected(irc-server.example-net.com)");
    assert_non_null(rule);
    assert_string_equal((char*)rule->arg[0], "irc-server.example-net.com");
    crule_free(&rule);
}

/* ========== Evaluation Tests ========== */

static void test_eval_functions_return_zero(void **state)
{
    (void)state;
    struct CRuleNode *rule;
    int result;

    /* All rule functions return 0 in test mode */
    rule = crule_parse("directop()");
    assert_non_null(rule);
    result = crule_eval(rule);
    assert_int_equal(result, 0);
    crule_free(&rule);

    /* NOT of 0 is 1 */
    rule = crule_parse("!directop()");
    assert_non_null(rule);
    result = crule_eval(rule);
    assert_int_equal(result, 1);
    crule_free(&rule);

    /* 0 && 0 = 0 */
    rule = crule_parse("directop() && connected(*)");
    assert_non_null(rule);
    result = crule_eval(rule);
    assert_int_equal(result, 0);
    crule_free(&rule);

    /* 0 || 0 = 0 */
    rule = crule_parse("directop() || connected(*)");
    assert_non_null(rule);
    result = crule_eval(rule);
    assert_int_equal(result, 0);
    crule_free(&rule);

    /* !0 || 0 = 1 */
    rule = crule_parse("!directop() || connected(*)");
    assert_non_null(rule);
    result = crule_eval(rule);
    assert_int_equal(result, 1);
    crule_free(&rule);
}

/* ========== Complex Expression Tests ========== */

static void test_parse_complex_expression(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("!directop() || !connected(hub.*)");
    assert_non_null(rule);
    crule_free(&rule);

    rule = crule_parse("(directop() || connected(hub.*)) && !connected(leaf.*)");
    assert_non_null(rule);
    crule_free(&rule);
}

static void test_parse_via_with_wildcards(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("via(hub.*.net, *.leaf.*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_via);
    assert_int_equal(rule->numargs, 2);
    assert_string_equal((char*)rule->arg[0], "hub.*.net");
    assert_string_equal((char*)rule->arg[1], "*.leaf.*");
    crule_free(&rule);
}

/* ========== Main ========== */

/* ========== Regression: missing operands (fuzz finding F23) ========== */

static void test_parse_missing_operand_fails_cleanly(void **state)
{
    (void)state;
    /* An && or || with nothing before it used to build a node around a
     * NULL child and free it on the error path. */
    assert_null(crule_parse("&&"));
    assert_null(crule_parse("||"));
    assert_null(crule_parse("\t\t&\t&"));
    assert_null(crule_parse("connected(a) && && connected(b)"));
    assert_null(crule_parse("connected(a) || || connected(b)"));
    assert_null(crule_parse("connected(a) &&"));
}

static void test_parse_too_many_arguments_fails(void **state)
{
    (void)state;
    /* F22: a fourth argument overflowed arg[CR_MAXARGS]. */
    assert_null(crule_parse("connected(a,b,c,d)"));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* Basic parsing */
        cmocka_unit_test(test_parse_empty_rule),
        cmocka_unit_test(test_parse_simple_function_no_args),
        cmocka_unit_test(test_parse_simple_function_one_arg),
        cmocka_unit_test(test_parse_simple_function_two_args),
        cmocka_unit_test(test_parse_directcon),

        /* NOT operator */
        cmocka_unit_test(test_parse_not_operator),
        cmocka_unit_test(test_parse_double_not),

        /* AND operator */
        cmocka_unit_test(test_parse_and_operator),
        cmocka_unit_test(test_parse_chained_and),

        /* OR operator */
        cmocka_unit_test(test_parse_or_operator),
        cmocka_unit_test(test_parse_chained_or),

        /* Precedence */
        cmocka_unit_test(test_parse_and_or_precedence),
        cmocka_unit_test(test_parse_parentheses_override),
        cmocka_unit_test(test_parse_nested_parentheses),

        /* Error handling */
        cmocka_unit_test(test_parse_unknown_function),
        cmocka_unit_test(test_parse_wrong_arg_count),
        cmocka_unit_test(test_parse_unclosed_paren),
        cmocka_unit_test(test_parse_unexpected_token),
        cmocka_unit_test(test_parse_invalid_characters),

        /* Whitespace */
        cmocka_unit_test(test_parse_extra_whitespace),
        cmocka_unit_test(test_parse_tabs),

        /* Colon terminator */
        cmocka_unit_test(test_parse_colon_terminator),

        /* Wildcards */
        cmocka_unit_test(test_parse_wildcard_patterns),
        cmocka_unit_test(test_parse_hostname_patterns),

        /* Evaluation */
        cmocka_unit_test(test_eval_functions_return_zero),

        /* Complex expressions */
        cmocka_unit_test(test_parse_complex_expression),
        cmocka_unit_test(test_parse_via_with_wildcards),
        cmocka_unit_test(test_parse_missing_operand_fails_cleanly),
        cmocka_unit_test(test_parse_too_many_arguments_fails),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
