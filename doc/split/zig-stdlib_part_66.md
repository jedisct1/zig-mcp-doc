```
son" {
    try err("[-012]");
}
test "n_number_neg_real_without_int_part.json" {
    try err("[-.123]");
}
test "n_number_neg_with_garbage_at_end.json" {
    try err("[-1x]");
}
test "n_number_real_garbage_after_e.json" {
    try err("[1ea]");
}
test "n_number_real_with_invalid_utf8_after_e.json" {
    try err("[1e\xe5]");
}
test "n_number_real_without_fractional_part.json" {
    try err("[1.]");
}
test "n_number_starting_with_dot.json" {
    try err("[.123]");
}
test "n_number_with_alpha.json" {
    try err("[1.2a-3]");
}
test "n_number_with_alpha_char.json" {
    try err("[1.8011670033376514H-308]");
}
test "n_number_with_leading_zero.json" {
    try err("[012]");
}
test "n_object_bad_value.json" {
    try err("[\"x\", truth]");
}
test "n_object_bracket_key.json" {
    try err("{[: \"x\"}\n");
}
test "n_object_comma_instead_of_colon.json" {
    try err("{\"x\", null}");
}
test "n_object_double_colon.json" {
    try err("{\"x\"::\"b\"}");
}
test "n_object_emoji.json" {
    try err("{\xf0\x9f\x87\xa8\xf0\x9f\x87\xad}");
}
test "n_object_garbage_at_end.json" {
    try err("{\"a\":\"a\" 123}");
}
test "n_object_key_with_single_quotes.json" {
    try err("{key: 'value'}");
}
test "n_object_lone_continuation_byte_in_key_and_trailing_comma.json" {
    try err("{\"\xb9\":\"0\",}");
}
test "n_object_missing_colon.json" {
    try err("{\"a\" b}");
}
test "n_object_missing_key.json" {
    try err("{:\"b\"}");
}
test "n_object_missing_semicolon.json" {
    try err("{\"a\" \"b\"}");
}
test "n_object_missing_value.json" {
    try err("{\"a\":");
}
test "n_object_no-colon.json" {
    try err("{\"a\"");
}
test "n_object_non_string_key.json" {
    try err("{1:1}");
}
test "n_object_non_string_key_but_huge_number_instead.json" {
    try err("{9999E9999:1}");
}
test "n_object_repeated_null_null.json" {
    try err("{null:null,null:null}");
}
test "n_object_several_trailing_commas.json" {
    try err("{\"id\":0,,,,,}");
}
test "n_object_single_quote.json" {
    try err("{'a':0}");
}
test "n_object_trailing_comma.json" {
    try err("{\"id\":0,}");
}
test "n_object_trailing_comment.json" {
    try err("{\"a\":\"b\"}/**/");
}
test "n_object_trailing_comment_open.json" {
    try err("{\"a\":\"b\"}/**//");
}
test "n_object_trailing_comment_slash_open.json" {
    try err("{\"a\":\"b\"}//");
}
test "n_object_trailing_comment_slash_open_incomplete.json" {
    try err("{\"a\":\"b\"}/");
}
test "n_object_two_commas_in_a_row.json" {
    try err("{\"a\":\"b\",,\"c\":\"d\"}");
}
test "n_object_unquoted_key.json" {
    try err("{a: \"b\"}");
}
test "n_object_unterminated-value.json" {
    try err("{\"a\":\"a");
}
test "n_object_with_single_string.json" {
    try err("{ \"foo\" : \"bar\", \"a\" }");
}
test "n_object_with_trailing_garbage.json" {
    try err("{\"a\":\"b\"}#");
}
test "n_single_space.json" {
    try err(" ");
}
test "n_string_1_surrogate_then_escape.json" {
    try err("[\"\\uD800\\\"]");
}
test "n_string_1_surrogate_then_escape_u.json" {
    try err("[\"\\uD800\\u\"]");
}
test "n_string_1_surrogate_then_escape_u1.json" {
    try err("[\"\\uD800\\u1\"]");
}
test "n_string_1_surrogate_then_escape_u1x.json" {
    try err("[\"\\uD800\\u1x\"]");
}
test "n_string_accentuated_char_no_quotes.json" {
    try err("[\xc3\xa9]");
}
test "n_string_backslash_00.json" {
    try err("[\"\\\x00\"]");
}
test "n_string_escape_x.json" {
    try err("[\"\\x00\"]");
}
test "n_string_escaped_backslash_bad.json" {
    try err("[\"\\\\\\\"]");
}
test "n_string_escaped_ctrl_char_tab.json" {
    try err("[\"\\\x09\"]");
}
test "n_string_escaped_emoji.json" {
    try err("[\"\\\xf0\x9f\x8c\x80\"]");
}
test "n_string_incomplete_escape.json" {
    try err("[\"\\\"]");
}
test "n_string_incomplete_escaped_character.json" {
    try err("[\"\\u00A\"]");
}
test "n_string_incomplete_surrogate.json" {
    try err("[\"\\uD834\\uDd\"]");
}
test "n_string_incomplete_surrogate_escape_invalid.json" {
    try err("[\"\\uD800\\uD800\\x\"]");
}
test "n_string_invalid-utf-8-in-escape.json" {
    try err("[\"\\u\xe5\"]");
}
test "n_string_invalid_backslash_esc.json" {
    try err("[\"\\a\"]");
}
test "n_string_invalid_unicode_escape.json" {
    try err("[\"\\uqqqq\"]");
}
test "n_string_invalid_utf8_after_escape.json" {
    try err("[\"\\\xe5\"]");
}
test "n_string_leading_uescaped_thinspace.json" {
    try err("[\\u0020\"asd\"]");
}
test "n_string_no_quotes_with_bad_escape.json" {
    try err("[\\n]");
}
test "n_string_single_doublequote.json" {
    try err("\"");
}
test "n_string_single_quote.json" {
    try err("['single quote']");
}
test "n_string_single_string_no_double_quotes.json" {
    try err("abc");
}
test "n_string_start_escape_unclosed.json" {
    try err("[\"\\");
}
test "n_string_unescaped_ctrl_char.json" {
    try err("[\"a\x00a\"]");
}
test "n_string_unescaped_newline.json" {
    try err("[\"new\nline\"]");
}
test "n_string_unescaped_tab.json" {
    try err("[\"\x09\"]");
}
test "n_string_unicode_CapitalU.json" {
    try err("\"\\UA66D\"");
}
test "n_string_with_trailing_garbage.json" {
    try err("\"\"x");
}
test "n_structure_100000_opening_arrays.json" {
    try err("[" ** 100000);
}
test "n_structure_U+2060_word_joined.json" {
    try err("[\xe2\x81\xa0]");
}
test "n_structure_UTF8_BOM_no_data.json" {
    try err("\xef\xbb\xbf");
}
test "n_structure_angle_bracket_..json" {
    try err("<.>");
}
test "n_structure_angle_bracket_null.json" {
    try err("[<null>]");
}
test "n_structure_array_trailing_garbage.json" {
    try err("[1]x");
}
test "n_structure_array_with_extra_array_close.json" {
    try err("[1]]");
}
test "n_structure_array_with_unclosed_string.json" {
    try err("[\"asd]");
}
test "n_structure_ascii-unicode-identifier.json" {
    try err("a\xc3\xa5");
}
test "n_structure_capitalized_True.json" {
    try err("[True]");
}
test "n_structure_close_unopened_array.json" {
    try err("1]");
}
test "n_structure_comma_instead_of_closing_brace.json" {
    try err("{\"x\": true,");
}
test "n_structure_double_array.json" {
    try err("[][]");
}
test "n_structure_end_array.json" {
    try err("]");
}
test "n_structure_incomplete_UTF8_BOM.json" {
    try err("\xef\xbb{}");
}
test "n_structure_lone-invalid-utf-8.json" {
    try err("\xe5");
}
test "n_structure_lone-open-bracket.json" {
    try err("[");
}
test "n_structure_no_data.json" {
    try err("");
}
test "n_structure_null-byte-outside-string.json" {
    try err("[\x00]");
}
test "n_structure_number_with_trailing_garbage.json" {
    try err("2@");
}
test "n_structure_object_followed_by_closing_object.json" {
    try err("{}}");
}
test "n_structure_object_unclosed_no_value.json" {
    try err("{\"\":");
}
test "n_structure_object_with_comment.json" {
    try err("{\"a\":/*comment*/\"b\"}");
}
test "n_structure_object_with_trailing_garbage.json" {
    try err("{\"a\": true} \"x\"");
}
test "n_structure_open_array_apostrophe.json" {
    try err("['");
}
test "n_structure_open_array_comma.json" {
    try err("[,");
}
test "n_structure_open_array_object.json" {
    try err("[{\"\":" ** 50000 ++ "\n");
}
test "n_structure_open_array_open_object.json" {
    try err("[{");
}
test "n_structure_open_array_open_string.json" {
    try err("[\"a");
}
test "n_structure_open_array_string.json" {
    try err("[\"a\"");
}
test "n_structure_open_object.json" {
    try err("{");
}
test "n_structure_open_object_close_array.json" {
    try err("{]");
}
test "n_structure_open_object_comma.json" {
    try err("{,");
}
test "n_structure_open_object_open_array.json" {
    try err("{[");
}
test "n_structure_open_object_open_string.json" {
    try err("{\"a");
}
test "n_structure_open_object_string_with_apostrophes.json" {
    try err("{'a'");
}
test "n_structure_open_open.json" {
    try err("[\"\\{[\"\\{[\"\\{[\"\\{");
}
test "n_structure_single_eacute.json" {
    try err("\xe9");
}
test "n_structure_single_star.json" {
    try err("*");
}
test "n_structure_trailing_#.json" {
    try err("{\"a\":\"b\"}#{}");
}
test "n_structure_uescaped_LF_before_string.json" {
    try err("[\\u000A\"\"]");
}
test "n_structure_unclosed_array.json" {
    try err("[1");
}
test "n_structure_unclosed_array_partial_null.json" {
    try err("[ false, nul");
}
test "n_structure_unclosed_array_unfinished_false.json" {
    try err("[ true, fals");
}
test "n_structure_unclosed_array_unfinished_true.json" {
    try err("[ false, tru");
}
test "n_structure_unclosed_object.json" {
    try err("{\"asd\":\"asd\"");
}
test "n_structure_unicode-identifier.json" {
    try err("\xc3\xa5");
}
test "n_structure_whitespace_U+2060_word_joiner.json" {
    try err("[\xe2\x81\xa0]");
}
test "n_structure_whitespace_formfeed.json" {
    try err("[\x0c]");
}
test "y_array_arraysWithSpaces.json" {
    try ok("[[]   ]");
}
test "y_array_empty-string.json" {
    try ok("[\"\"]");
}
test "y_array_empty.json" {
    try ok("[]");
}
test "y_array_ending_with_newline.json" {
    try ok("[\"a\"]");
}
test "y_array_false.json" {
    try ok("[false]");
}
test "y_array_heterogeneous.json" {
    try ok("[null, 1, \"1\", {}]");
}
test "y_array_null.json" {
    try ok("[null]");
}
test "y_array_with_1_and_newline.json" {
    try ok("[1\n]");
}
test "y_array_with_leading_space.json" {
    try ok(" [1]");
}
test "y_array_with_several_null.json" {
    try ok("[1,null,null,null,2]");
}
test "y_array_with_trailing_space.json" {
    try ok("[2] ");
}
test "y_number.json" {
    try ok("[123e65]");
}
test "y_number_0e+1.json" {
    try ok("[0e+1]");
}
test "y_number_0e1.json" {
    try ok("[0e1]");
}
test "y_number_after_space.json" {
    try ok("[ 4]");
}
test "y_number_double_close_to_zero.json" {
    try ok("[-0.000000000000000000000000000000000000000000000000000000000000000000000000000001]\n");
}
test "y_number_int_with_exp.json" {
    try ok("[20e1]");
}
test "y_number_minus_zero.json" {
    try ok("[-0]");
}
test "y_number_negative_int.json" {
    try ok("[-123]");
}
test "y_number_negative_one.json" {
    try ok("[-1]");
}
test "y_number_negative_zero.json" {
    try ok("[-0]");
}
test "y_number_real_capital_e.json" {
    try ok("[1E22]");
}
test "y_number_real_capital_e_neg_exp.json" {
    try ok("[1E-2]");
}
test "y_number_real_capital_e_pos_exp.json" {
    try ok("[1E+2]");
}
test "y_number_real_exponent.json" {
    try ok("[123e45]");
}
test "y_number_real_fraction_exponent.json" {
    try ok("[123.456e78]");
}
test "y_number_real_neg_exp.json" {
    try ok("[1e-2]");
}
test "y_number_real_pos_exponent.json" {
    try ok("[1e+2]");
}
test "y_number_simple_int.json" {
    try ok("[123]");
}
test "y_number_simple_real.json" {
    try ok("[123.456789]");
}
test "y_object.json" {
    try ok("{\"asd\":\"sdf\", \"dfg\":\"fgh\"}");
}
test "y_object_basic.json" {
    try ok("{\"asd\":\"sdf\"}");
}
test "y_object_duplicated_key.json" {
    try ok("{\"a\":\"b\",\"a\":\"c\"}");
}
test "y_object_duplicated_key_and_value.json" {
    try ok("{\"a\":\"b\",\"a\":\"b\"}");
}
test "y_object_empty.json" {
    try ok("{}");
}
test "y_object_empty_key.json" {
    try ok("{\"\":0}");
}
test "y_object_escaped_null_in_key.json" {
    try ok("{\"foo\\u0000bar\": 42}");
}
test "y_object_extreme_numbers.json" {
    try ok("{ \"min\": -1.0e+28, \"max\": 1.0e+28 }");
}
test "y_object_long_strings.json" {
    try ok("{\"x\":[{\"id\": \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}], \"id\": \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}");
}
test "y_object_simple.json" {
    try ok("{\"a\":[]}");
}
test "y_object_string_unicode.json" {
    try ok("{\"title\":\"\\u041f\\u043e\\u043b\\u0442\\u043e\\u0440\\u0430 \\u0417\\u0435\\u043c\\u043b\\u0435\\u043a\\u043e\\u043f\\u0430\" }");
}
test "y_object_with_newlines.json" {
    try ok("{\n\"a\": \"b\"\n}");
}
test "y_string_1_2_3_bytes_UTF-8_sequences.json" {
    try ok("[\"\\u0060\\u012a\\u12AB\"]");
}
test "y_string_accepted_surrogate_pair.json" {
    try ok("[\"\\uD801\\udc37\"]");
}
test "y_string_accepted_surrogate_pairs.json" {
    try ok("[\"\\ud83d\\ude39\\ud83d\\udc8d\"]");
}
test "y_string_allowed_escapes.json" {
    try ok("[\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"]");
}
test "y_string_backslash_and_u_escaped_zero.json" {
    try ok("[\"\\\\u0000\"]");
}
test "y_string_backslash_doublequotes.json" {
    try ok("[\"\\\"\"]");
}
test "y_string_comments.json" {
    try ok("[\"a/*b*/c/*d//e\"]");
}
test "y_string_double_escape_a.json" {
    try ok("[\"\\\\a\"]");
}
test "y_string_double_escape_n.json" {
    try ok("[\"\\\\n\"]");
}
test "y_string_escaped_control_character.json" {
    try ok("[\"\\u0012\"]");
}
test "y_string_escaped_noncharacter.json" {
    try ok("[\"\\uFFFF\"]");
}
test "y_string_in_array.json" {
    try ok("[\"asd\"]");
}
test "y_string_in_array_with_leading_space.json" {
    try ok("[ \"asd\"]");
}
test "y_string_last_surrogates_1_and_2.json" {
    try ok("[\"\\uDBFF\\uDFFF\"]");
}
test "y_string_nbsp_uescaped.json" {
    try ok("[\"new\\u00A0line\"]");
}
test "y_string_nonCharacterInUTF-8_U+10FFFF.json" {
    try ok("[\"\xf4\x8f\xbf\xbf\"]");
}
test "y_string_nonCharacterInUTF-8_U+FFFF.json" {
    try ok("[\"\xef\xbf\xbf\"]");
}
test "y_string_null_escape.json" {
    try ok("[\"\\u0000\"]");
}
test "y_string_one-byte-utf-8.json" {
    try ok("[\"\\u002c\"]");
}
test "y_string_pi.json" {
    try ok("[\"\xcf\x80\"]");
}
test "y_string_reservedCharacterInUTF-8_U+1BFFF.json" {
    try ok("[\"\xf0\x9b\xbf\xbf\"]");
}
test "y_string_simple_ascii.json" {
    try ok("[\"asd \"]");
}
test "y_string_space.json" {
    try ok("\" \"");
}
test "y_string_surrogates_U+1D11E_MUSICAL_SYMBOL_G_CLEF.json" {
    try ok("[\"\\uD834\\uDd1e\"]");
}
test "y_string_three-byte-utf-8.json" {
    try ok("[\"\\u0821\"]");
}
test "y_string_two-byte-utf-8.json" {
    try ok("[\"\\u0123\"]");
}
test "y_string_u+2028_line_sep.json" {
    try ok("[\"\xe2\x80\xa8\"]");
}
test "y_string_u+2029_par_sep.json" {
    try ok("[\"\xe2\x80\xa9\"]");
}
test "y_string_uEscape.json" {
    try ok("[\"\\u0061\\u30af\\u30EA\\u30b9\"]");
}
test "y_string_uescaped_newline.json" {
    try ok("[\"new\\u000Aline\"]");
}
test "y_string_unescaped_char_delete.json" {
    try ok("[\"\x7f\"]");
}
test "y_string_unicode.json" {
    try ok("[\"\\uA66D\"]");
}
test "y_string_unicodeEscapedBackslash.json" {
    try ok("[\"\\u005C\"]");
}
test "y_string_unicode_2.json" {
    try ok("[\"\xe2\x8d\x82\xe3\x88\xb4\xe2\x8d\x82\"]");
}
test "y_string_unicode_U+10FFFE_nonchar.json" {
    try ok("[\"\\uDBFF\\uDFFE\"]");
}
test "y_string_unicode_U+1FFFE_nonchar.json" {
    try ok("[\"\\uD83F\\uDFFE\"]");
}
test "y_string_unicode_U+200B_ZERO_WIDTH_SPACE.json" {
    try ok("[\"\\u200B\"]");
}
test "y_string_unicode_U+2064_invisible_plus.json" {
    try ok("[\"\\u2064\"]");
}
test "y_string_unicode_U+FDD0_nonchar.json" {
    try ok("[\"\\uFDD0\"]");
}
test "y_string_unicode_U+FFFE_nonchar.json" {
    try ok("[\"\\uFFFE\"]");
}
test "y_string_unicode_escaped_double_quote.json" {
    try ok("[\"\\u0022\"]");
}
test "y_string_utf8.json" {
    try ok("[\"\xe2\x82\xac\xf0\x9d\x84\x9e\"]");
}
test "y_string_with_del_character.json" {
    try ok("[\"a\x7fa\"]");
}
test "y_structure_lonely_false.json" {
    try ok("false");
}
test "y_structure_lonely_int.json" {
    try ok("42");
}
test "y_structure_lonely_negative_real.json" {
    try ok("-0.1");
}
test "y_structure_lonely_null.json" {
    try ok("null");
}
test "y_structure_lonely_string.json" {
    try ok("\"asd\"");
}
test "y_structure_lonely_true.json" {
    try ok("true");
}
test "y_structure_string_empty.json" {
    try ok("\"\"");
}
test "y_structure_trailing_newline.json" {
    try ok("[\"a\"]\n");
}
test "y_structure_true_in_array.json" {
    try ok("[true]");
}
test "y_structure_whitespace_array.json" {
    try ok(" [] ");
}
const std = @import("std");
const JsonScanner = @import("./scanner.zig").Scanner;
const jsonReader = @import("./scanner.zig").reader;
const JsonReader = @import("./scanner.zig").Reader;
const Token = @import("./scanner.zig").Token;
const TokenType = @import("./scanner.zig").TokenType;
const Diagnostics = @import("./scanner.zig").Diagnostics;
const Error = @import("./scanner.zig").Error;
const validate = @import("./scanner.zig").validate;
const isNumberFormattedLikeAnInteger = @import("./scanner.zig").isNumberFormattedLikeAnInteger;

const example_document_str =
    \\{
    \\  "Image": {
    \\      "Width":  800,
    \\      "Height": 600,
    \\      "Title":  "View from 15th Floor",
    \\      "Thumbnail": {
    \\          "Url":    "http://www.example.com/image/481989943",
    \\          "Height": 125,
    \\          "Width":  100
    \\      },
    \\      "Animated" : false,
    \\      "IDs": [116, 943, 234, 38793]
    \\    }
    \\}
;

fn expectNext(scanner_or_reader: anytype, expected_token: Token) !void {
    return expectEqualTokens(expected_token, try scanner_or_reader.next());
}

fn expectPeekNext(scanner_or_reader: anytype, expected_token_type: TokenType, expected_token: Token) !void {
    try std.testing.expectEqual(expected_token_type, try scanner_or_reader.peekNextTokenType());
    try expectEqualTokens(expected_token, try scanner_or_reader.next());
}

test "token" {
    var scanner = JsonScanner.initCompleteInput(std.testing.allocator, example_document_str);
    defer scanner.deinit();

    try expectNext(&scanner, .object_begin);
    try expectNext(&scanner, Token{ .string = "Image" });
    try expectNext(&scanner, .object_begin);
    try expectNext(&scanner, Token{ .string = "Width" });
    try expectNext(&scanner, Token{ .number = "800" });
    try expectNext(&scanner, Token{ .string = "Height" });
    try expectNext(&scanner, Token{ .number = "600" });
    try expectNext(&scanner, Token{ .string = "Title" });
    try expectNext(&scanner, Token{ .string = "View from 15th Floor" });
    try expectNext(&scanner, Token{ .string = "Thumbnail" });
    try expectNext(&scanner, .object_begin);
    try expectNext(&scanner, Token{ .string = "Url" });
    try expectNext(&scanner, Token{ .string = "http://www.example.com/image/481989943" });
    try expectNext(&scanner, Token{ .string = "Height" });
    try expectNext(&scanner, Token{ .number = "125" });
    try expectNext(&scanner, Token{ .string = "Width" });
    try expectNext(&scanner, Token{ .number = "100" });
    try expectNext(&scanner, .object_end);
    try expectNext(&scanner, Token{ .string = "Animated" });
    try expectNext(&scanner, .false);
    try expectNext(&scanner, Token{ .string = "IDs" });
    try expectNext(&scanner, .array_begin);
    try expectNext(&scanner, Token{ .number = "116" });
    try expectNext(&scanner, Token{ .number = "943" });
    try expectNext(&scanner, Token{ .number = "234" });
    try expectNext(&scanner, Token{ .number = "38793" });
    try expectNext(&scanner, .array_end);
    try expectNext(&scanner, .object_end);
    try expectNext(&scanner, .object_end);
    try expectNext(&scanner, .end_of_document);
}

const all_types_test_case =
    \\[
    \\  "", "a\nb",
    \\  0, 0.0, -1.1e-1,
    \\  true, false, null,
    \\  {"a": {}},
    \\  []
    \\]
;

fn testAllTypes(source: anytype, large_buffer: bool) !void {
    try expectPeekNext(source, .array_begin, .array_begin);
    try expectPeekNext(source, .string, Token{ .string = "" });
    try expectPeekNext(source, .string, Token{ .partial_string = "a" });
    try expectPeekNext(source, .string, Token{ .partial_string_escaped_1 = "\n".* });
    if (large_buffer) {
        try expectPeekNext(source, .string, Token{ .string = "b" });
    } else {
        try expectPeekNext(source, .string, Token{ .partial_string = "b" });
        try expectPeekNext(source, .string, Token{ .string = "" });
    }
    if (large_buffer) {
        try expectPeekNext(source, .number, Token{ .number = "0" });
    } else {
        try expectPeekNext(source, .number, Token{ .partial_number = "0" });
        try expectPeekNext(source, .number, Token{ .number = "" });
    }
    if (large_buffer) {
        try expectPeekNext(source, .number, Token{ .number = "0.0" });
    } else {
        try expectPeekNext(source, .number, Token{ .partial_number = "0" });
        try expectPeekNext(source, .number, Token{ .partial_number = "." });
        try expectPeekNext(source, .number, Token{ .partial_number = "0" });
        try expectPeekNext(source, .number, Token{ .number = "" });
    }
    if (large_buffer) {
        try expectPeekNext(source, .number, Token{ .number = "-1.1e-1" });
    } else {
        try expectPeekNext(source, .number, Token{ .partial_number = "-" });
        try expectPeekNext(source, .number, Token{ .partial_number = "1" });
        try expectPeekNext(source, .number, Token{ .partial_number = "." });
        try expectPeekNext(source, .number, Token{ .partial_number = "1" });
        try expectPeekNext(source, .number, Token{ .partial_number = "e" });
        try expectPeekNext(source, .number, Token{ .partial_number = "-" });
        try expectPeekNext(source, .number, Token{ .partial_number = "1" });
        try expectPeekNext(source, .number, Token{ .number = "" });
    }
    try expectPeekNext(source, .true, .true);
    try expectPeekNext(source, .false, .false);
    try expectPeekNext(source, .null, .null);
    try expectPeekNext(source, .object_begin, .object_begin);
    if (large_buffer) {
        try expectPeekNext(source, .string, Token{ .string = "a" });
    } else {
        try expectPeekNext(source, .string, Token{ .partial_string = "a" });
        try expectPeekNext(source, .string, Token{ .string = "" });
    }
    try expectPeekNext(source, .object_begin, .object_begin);
    try expectPeekNext(source, .object_end, .object_end);
    try expectPeekNext(source, .object_end, .object_end);
    try expectPeekNext(source, .array_begin, .array_begin);
    try expectPeekNext(source, .array_end, .array_end);
    try expectPeekNext(source, .array_end, .array_end);
    try expectPeekNext(source, .end_of_document, .end_of_document);
}

test "peek all types" {
    var scanner = JsonScanner.initCompleteInput(std.testing.allocator, all_types_test_case);
    defer scanner.deinit();
    try testAllTypes(&scanner, true);

    var stream = std.io.fixedBufferStream(all_types_test_case);
    var json_reader = jsonReader(std.testing.allocator, stream.reader());
    defer json_reader.deinit();
    try testAllTypes(&json_reader, true);

    var tiny_stream = std.io.fixedBufferStream(all_types_test_case);
    var tiny_json_reader = JsonReader(1, @TypeOf(tiny_stream.reader())).init(std.testing.allocator, tiny_stream.reader());
    defer tiny_json_reader.deinit();
    try testAllTypes(&tiny_json_reader, false);
}

test "token mismatched close" {
    var scanner = JsonScanner.initCompleteInput(std.testing.allocator, "[102, 111, 111 }");
    defer scanner.deinit();
    try expectNext(&scanner, .array_begin);
    try expectNext(&scanner, Token{ .number = "102" });
    try expectNext(&scanner, Token{ .number = "111" });
    try expectNext(&scanner, Token{ .number = "111" });
    try std.testing.expectError(error.SyntaxError, scanner.next());
}

test "token premature object close" {
    var scanner = JsonScanner.initCompleteInput(std.testing.allocator, "{ \"key\": }");
    defer scanner.deinit();
    try expectNext(&scanner, .object_begin);
    try expectNext(&scanner, Token{ .string = "key" });
    try std.testing.expectError(error.SyntaxError, scanner.next());
}

test "JsonScanner basic" {
    var scanner = JsonScanner.initCompleteInput(std.testing.allocator, example_document_str);
    defer scanner.deinit();

    while (true) {
        const token = try scanner.next();
        if (token == .end_of_document) break;
    }
}

test "JsonReader basic" {
    var stream = std.io.fixedBufferStream(example_document_str);

    var json_reader = jsonReader(std.testing.allocator, stream.reader());
    defer json_reader.deinit();

    while (true) {
        const token = try json_reader.next();
        if (token == .end_of_document) break;
    }
}

const number_test_stems = .{
    .{ "", "-" },
    .{ "0", "1", "10", "9999999999999999999999999" },
    .{ "", ".0", ".999999999999999999999999" },
    .{ "", "e0", "E0", "e+0", "e-0", "e9999999999999999999999999999" },
};
const number_test_items = blk: {
    var ret: []const []const u8 = &[_][]const u8{};
    for (number_test_stems[0]) |s0| {
        for (number_test_stems[1]) |s1| {
            for (number_test_stems[2]) |s2| {
                for (number_test_stems[3]) |s3| {
                    ret = ret ++ &[_][]const u8{s0 ++ s1 ++ s2 ++ s3};
                }
            }
        }
    }
    break :blk ret;
};

test "numbers" {
    for (number_test_items) |number_str| {
        var scanner = JsonScanner.initCompleteInput(std.testing.allocator, number_str);
        defer scanner.deinit();

        const token = try scanner.next();
        const value = token.number; // assert this is a number
        try std.testing.expectEqualStrings(number_str, value);

        try std.testing.expectEqual(Token.end_of_document, try scanner.next());
    }
}

const string_test_cases = .{
    // The left is JSON without the "quotes".
    // The right is the expected unescaped content.
    .{ "", "" },
    .{ "\\\\", "\\" },
    .{ "a\\\\b", "a\\b" },
    .{ "a\\\"b", "a\"b" },
    .{ "\\n", "\n" },
    .{ "\\u000a", "\n" },
    .{ "𝄞", "\u{1D11E}" },
    .{ "\\uD834\\uDD1E", "\u{1D11E}" },
    .{ "\\uD87F\\uDFFE", "\u{2FFFE}" },
    .{ "\\uff20", "＠" },
};

test "strings" {
    inline for (string_test_cases) |tuple| {
        var stream = std.io.fixedBufferStream("\"" ++ tuple[0] ++ "\"");
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var json_reader = jsonReader(std.testing.allocator, stream.reader());
        defer json_reader.deinit();

        const token = try json_reader.nextAlloc(arena.allocator(), .alloc_if_needed);
        const value = switch (token) {
            .string => |value| value,
            .allocated_string => |value| value,
            else => return error.ExpectedString,
        };
        try std.testing.expectEqualStrings(tuple[1], value);

        try std.testing.expectEqual(Token.end_of_document, try json_reader.next());
    }
}

const nesting_test_cases = .{
    .{ null, "[]" },
    .{ null, "{}" },
    .{ error.SyntaxError, "[}" },
    .{ error.SyntaxError, "{]" },
    .{ null, "[" ** 1000 ++ "]" ** 1000 },
    .{ null, "{\"\":" ** 1000 ++ "0" ++ "}" ** 1000 },
    .{ error.SyntaxError, "[" ** 1000 ++ "]" ** 999 ++ "}" },
    .{ error.SyntaxError, "{\"\":" ** 1000 ++ "0" ++ "}" ** 999 ++ "]" },
    .{ error.SyntaxError, "[" ** 1000 ++ "]" ** 1001 },
    .{ error.SyntaxError, "{\"\":" ** 1000 ++ "0" ++ "}" ** 1001 },
    .{ error.UnexpectedEndOfInput, "[" ** 1000 ++ "]" ** 999 },
    .{ error.UnexpectedEndOfInput, "{\"\":" ** 1000 ++ "0" ++ "}" ** 999 },
};

test "nesting" {
    inline for (nesting_test_cases) |tuple| {
        const maybe_error = tuple[0];
        const document_str = tuple[1];

        expectMaybeError(document_str, maybe_error) catch |err| {
            std.debug.print("in json document: {s}\n", .{document_str});
            return err;
        };
    }
}

fn expectMaybeError(document_str: []const u8, maybe_error: ?Error) !void {
    var scanner = JsonScanner.initCompleteInput(std.testing.allocator, document_str);
    defer scanner.deinit();

    while (true) {
        const token = scanner.next() catch |err| {
            if (maybe_error) |expected_err| {
                if (err == expected_err) return;
            }
            return err;
        };
        if (token == .end_of_document) break;
    }
    if (maybe_error != null) return error.ExpectedError;
}

fn expectEqualTokens(expected_token: Token, actual_token: Token) !void {
    try std.testing.expectEqual(std.meta.activeTag(expected_token), std.meta.activeTag(actual_token));
    switch (expected_token) {
        .number => |expected_value| {
            try std.testing.expectEqualStrings(expected_value, actual_token.number);
        },
        .allocated_number => |expected_value| {
            try std.testing.expectEqualStrings(expected_value, actual_token.allocated_number);
        },
        .partial_number => |expected_value| {
            try std.testing.expectEqualStrings(expected_value, actual_token.partial_number);
        },

        .string => |expected_value| {
            try std.testing.expectEqualStrings(expected_value, actual_token.string);
        },
        .allocated_string => |expected_value| {
            try std.testing.expectEqualStrings(expected_value, actual_token.allocated_string);
        },
        .partial_string => |expected_value| {
            try std.testing.expectEqualStrings(expected_value, actual_token.partial_string);
        },
        .partial_string_escaped_1 => |expected_value| {
            try std.testing.expectEqualStrings(&expected_value, &actual_token.partial_string_escaped_1);
        },
        .partial_string_escaped_2 => |expected_value| {
            try std.testing.expectEqualStrings(&expected_value, &actual_token.partial_string_escaped_2);
        },
        .partial_string_escaped_3 => |expected_value| {
            try std.testing.expectEqualStrings(&expected_value, &actual_token.partial_string_escaped_3);
        },
        .partial_string_escaped_4 => |expected_value| {
            try std.testing.expectEqualStrings(&expected_value, &actual_token.partial_string_escaped_4);
        },

        .object_begin,
        .object_end,
        .array_begin,
        .array_end,
        .true,
        .false,
        .null,
        .end_of_document,
        => {},
    }
}

fn testTinyBufferSize(document_str: []const u8) !void {
    var tiny_stream = std.io.fixedBufferStream(document_str);
    var normal_stream = std.io.fixedBufferStream(document_str);

    var tiny_json_reader = JsonReader(1, @TypeOf(tiny_stream.reader())).init(std.testing.allocator, tiny_stream.reader());
    defer tiny_json_reader.deinit();
    var normal_json_reader = JsonReader(0x1000, @TypeOf(normal_stream.reader())).init(std.testing.allocator, normal_stream.reader());
    defer normal_json_reader.deinit();

    expectEqualStreamOfTokens(&normal_json_reader, &tiny_json_reader) catch |err| {
        std.debug.print("in json document: {s}\n", .{document_str});
        return err;
    };
}
fn expectEqualStreamOfTokens(control_json_reader: anytype, test_json_reader: anytype) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    while (true) {
        const control_token = try control_json_reader.nextAlloc(arena.allocator(), .alloc_always);
        const test_token = try test_json_reader.nextAlloc(arena.allocator(), .alloc_always);
        try expectEqualTokens(control_token, test_token);
        if (control_token == .end_of_document) break;
        _ = arena.reset(.retain_capacity);
    }
}

test "BufferUnderrun" {
    try testTinyBufferSize(example_document_str);
    for (number_test_items) |number_str| {
        try testTinyBufferSize(number_str);
    }
    inline for (string_test_cases) |tuple| {
        try testTinyBufferSize("\"" ++ tuple[0] ++ "\"");
    }
}

test "validate" {
    try std.testing.expectEqual(true, try validate(std.testing.allocator, "{}"));
    try std.testing.expectEqual(true, try validate(std.testing.allocator, "[]"));
    try std.testing.expectEqual(false, try validate(std.testing.allocator, "[{[[[[{}]]]]}]"));
    try std.testing.expectEqual(false, try validate(std.testing.allocator, "{]"));
    try std.testing.expectEqual(false, try validate(std.testing.allocator, "[}"));
    try std.testing.expectEqual(false, try validate(std.testing.allocator, "{{{{[]}}}]"));
}

fn testSkipValue(s: []const u8) !void {
    var scanner = JsonScanner.initCompleteInput(std.testing.allocator, s);
    defer scanner.deinit();
    try scanner.skipValue();
    try expectEqualTokens(.end_of_document, try scanner.next());

    var stream = std.io.fixedBufferStream(s);
    var json_reader = jsonReader(std.testing.allocator, stream.reader());
    defer json_reader.deinit();
    try json_reader.skipValue();
    try expectEqualTokens(.end_of_document, try json_reader.next());
}

test "skipValue" {
    try testSkipValue("false");
    try testSkipValue("true");
    try testSkipValue("null");
    try testSkipValue("42");
    try testSkipValue("42.0");
    try testSkipValue("\"foo\"");
    try testSkipValue("[101, 111, 121]");
    try testSkipValue("{}");
    try testSkipValue("{\"foo\": \"bar\\nbaz\"}");

    // An absurd number of nestings
    const nestings = 1000;
    try testSkipValue("[" ** nestings ++ "]" ** nestings);

    // Would a number token cause problems in a deeply-nested array?
    try testSkipValue("[" ** nestings ++ "0.118, 999, 881.99, 911.9, 725, 3" ++ "]" ** nestings);

    // Mismatched brace/square bracket
    try std.testing.expectError(error.SyntaxError, testSkipValue("[102, 111, 111}"));
}

fn testEnsureStackCapacity(do_ensure: bool) !void {
    var fail_alloc = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    const failing_allocator = fail_alloc.allocator();

    const nestings = 2049; // intentionally not a power of 2.
    var input_string: std.ArrayListUnmanaged(u8) = .empty;
    try input_string.appendNTimes(std.testing.allocator, '[', nestings);
    try input_string.appendNTimes(std.testing.allocator, ']', nestings);
    defer input_string.deinit(std.testing.allocator);

    var scanner = JsonScanner.initCompleteInput(failing_allocator, input_string.items);
    defer scanner.deinit();

    if (do_ensure) {
        try scanner.ensureTotalStackCapacity(nestings);
    }

    try scanner.skipValue();
    try std.testing.expectEqual(Token.end_of_document, try scanner.next());
}
test "ensureTotalStackCapacity" {
    // Once to demonstrate failure.
    try std.testing.expectError(error.OutOfMemory, testEnsureStackCapacity(false));
    // Then to demonstrate it works.
    try testEnsureStackCapacity(true);
}

fn testDiagnosticsFromSource(expected_error: ?anyerror, line: u64, col: u64, byte_offset: u64, source: anytype) !void {
    var diagnostics = Diagnostics{};
    source.enableDiagnostics(&diagnostics);

    if (expected_error) |expected_err| {
        try std.testing.expectError(expected_err, source.skipValue());
    } else {
        try source.skipValue();
        try std.testing.expectEqual(Token.end_of_document, try source.next());
    }
    try std.testing.expectEqual(line, diagnostics.getLine());
    try std.testing.expectEqual(col, diagnostics.getColumn());
    try std.testing.expectEqual(byte_offset, diagnostics.getByteOffset());
}
fn testDiagnostics(expected_error: ?anyerror, line: u64, col: u64, byte_offset: u64, s: []const u8) !void {
    var scanner = JsonScanner.initCompleteInput(std.testing.allocator, s);
    defer scanner.deinit();
    try testDiagnosticsFromSource(expected_error, line, col, byte_offset, &scanner);

    var tiny_stream = std.io.fixedBufferStream(s);
    var tiny_json_reader = JsonReader(1, @TypeOf(tiny_stream.reader())).init(std.testing.allocator, tiny_stream.reader());
    defer tiny_json_reader.deinit();
    try testDiagnosticsFromSource(expected_error, line, col, byte_offset, &tiny_json_reader);

    var medium_stream = std.io.fixedBufferStream(s);
    var medium_json_reader = JsonReader(5, @TypeOf(medium_stream.reader())).init(std.testing.allocator, medium_stream.reader());
    defer medium_json_reader.deinit();
    try testDiagnosticsFromSource(expected_error, line, col, byte_offset, &medium_json_reader);
}
test "enableDiagnostics" {
    try testDiagnostics(error.UnexpectedEndOfInput, 1, 1, 0, "");
    try testDiagnostics(null, 1, 3, 2, "[]");
    try testDiagnostics(null, 2, 2, 3, "[\n]");
    try testDiagnostics(null, 14, 2, example_document_str.len, example_document_str);

    try testDiagnostics(error.SyntaxError, 3, 1, 25,
        \\{
        \\  "common": "mistake",
        \\}
    );

    inline for ([_]comptime_int{ 5, 6, 7, 99 }) |reps| {
        // The error happens 1 byte before the end.
        const s = "[" ** reps ++ "}";
        try testDiagnostics(error.SyntaxError, 1, s.len, s.len - 1, s);
    }
}

test isNumberFormattedLikeAnInteger {
    try std.testing.expect(isNumberFormattedLikeAnInteger("0"));
    try std.testing.expect(isNumberFormattedLikeAnInteger("1"));
    try std.testing.expect(isNumberFormattedLikeAnInteger("123"));
    try std.testing.expect(!isNumberFormattedLikeAnInteger("-0"));
    try std.testing.expect(!isNumberFormattedLikeAnInteger("0.0"));
    try std.testing.expect(!isNumberFormattedLikeAnInteger("1.0"));
    try std.testing.expect(!isNumberFormattedLikeAnInteger("1.23"));
    try std.testing.expect(!isNumberFormattedLikeAnInteger("1e10"));
    try std.testing.expect(!isNumberFormattedLikeAnInteger("1E10"));
}
// Notes on standards compliance: https://datatracker.ietf.org/doc/html/rfc8259
// * RFC 8259 requires JSON documents be valid UTF-8,
//   but makes an allowance for systems that are "part of a closed ecosystem".
//   I have no idea what that's supposed to mean in the context of a standard specification.
//   This implementation requires inputs to be valid UTF-8.
// * RFC 8259 contradicts itself regarding whether lowercase is allowed in \u hex digits,
//   but this is probably a bug in the spec, and it's clear that lowercase is meant to be allowed.
//   (RFC 5234 defines HEXDIG to only allow uppercase.)
// * When RFC 8259 refers to a "character", I assume they really mean a "Unicode scalar value".
//   See http://www.unicode.org/glossary/#unicode_scalar_value .
// * RFC 8259 doesn't explicitly disallow unpaired surrogate halves in \u escape sequences,
//   but vaguely implies that \u escapes are for encoding Unicode "characters" (i.e. Unicode scalar values?),
//   which would mean that unpaired surrogate halves are forbidden.
//   By contrast ECMA-404 (a competing(/compatible?) JSON standard, which JavaScript's JSON.parse() conforms to)
//   explicitly allows unpaired surrogate halves.
//   This implementation forbids unpaired surrogate halves in \u sequences.
//   If a high surrogate half appears in a \u sequence,
//   then a low surrogate half must immediately follow in \u notation.
// * RFC 8259 allows implementations to "accept non-JSON forms or extensions".
//   This implementation does not accept any of that.
// * RFC 8259 allows implementations to put limits on "the size of texts",
//   "the maximum depth of nesting", "the range and precision of numbers",
//   and "the length and character contents of strings".
//   This low-level implementation does not limit these,
//   except where noted above, and except that nesting depth requires memory allocation.
//   Note that this low-level API does not interpret numbers numerically,
//   but simply emits their source form for some higher level code to make sense of.
// * This low-level implementation allows duplicate object keys,
//   and key/value pairs are emitted in the order they appear in the input.

const std = @import("std");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const assert = std.debug.assert;
const BitStack = std.BitStack;

/// Scan the input and check for malformed JSON.
/// On `SyntaxError` or `UnexpectedEndOfInput`, returns `false`.
/// Returns any errors from the allocator as-is, which is unlikely,
/// but can be caused by extreme nesting depth in the input.
pub fn validate(allocator: Allocator, s: []const u8) Allocator.Error!bool {
    var scanner = Scanner.initCompleteInput(allocator, s);
    defer scanner.deinit();

    while (true) {
        const token = scanner.next() catch |err| switch (err) {
            error.SyntaxError, error.UnexpectedEndOfInput => return false,
            error.OutOfMemory => return error.OutOfMemory,
            error.BufferUnderrun => unreachable,
        };
        if (token == .end_of_document) break;
    }

    return true;
}

/// The parsing errors are divided into two categories:
///  * `SyntaxError` is for clearly malformed JSON documents,
///    such as giving an input document that isn't JSON at all.
///  * `UnexpectedEndOfInput` is for signaling that everything's been
///    valid so far, but the input appears to be truncated for some reason.
/// Note that a completely empty (or whitespace-only) input will give `UnexpectedEndOfInput`.
pub const Error = error{ SyntaxError, UnexpectedEndOfInput };

/// Calls `std.json.Reader` with `std.json.default_buffer_size`.
pub fn reader(allocator: Allocator, io_reader: anytype) Reader(default_buffer_size, @TypeOf(io_reader)) {
    return Reader(default_buffer_size, @TypeOf(io_reader)).init(allocator, io_reader);
}
/// Used by `json.reader`.
pub const default_buffer_size = 0x1000;

/// The tokens emitted by `std.json.Scanner` and `std.json.Reader` `.next*()` functions follow this grammar:
/// ```
///  <document> = <value> .end_of_document
///  <value> =
///    | <object>
///    | <array>
///    | <number>
///    | <string>
///    | .true
///    | .false
///    | .null
///  <object> = .object_begin ( <string> <value> )* .object_end
///  <array> = .array_begin ( <value> )* .array_end
///  <number> = <It depends. See below.>
///  <string> = <It depends. See below.>
/// ```
///
/// What you get for `<number>` and `<string>` values depends on which `next*()` method you call:
///
/// ```
/// next():
///  <number> = ( .partial_number )* .number
///  <string> = ( <partial_string> )* .string
///  <partial_string> =
///    | .partial_string
///    | .partial_string_escaped_1
///    | .partial_string_escaped_2
///    | .partial_string_escaped_3
///    | .partial_string_escaped_4
///
/// nextAlloc*(..., .alloc_always):
///  <number> = .allocated_number
///  <string> = .allocated_string
///
/// nextAlloc*(..., .alloc_if_needed):
///  <number> =
///    | .number
///    | .allocated_number
///  <string> =
///    | .string
///    | .allocated_string
/// ```
///
/// For all tokens with a `[]const u8`, `[]u8`, or `[n]u8` payload, the payload represents the content of the value.
/// For number values, this is the representation of the number exactly as it appears in the input.
/// For strings, this is the content of the string after resolving escape sequences.
///
/// For `.allocated_number` and `.allocated_string`, the `[]u8` payloads are allocations made with the given allocator.
/// You are responsible for managing that memory. `json.Reader.deinit()` does *not* free those allocations.
///
/// The `.partial_*` tokens indicate that a value spans multiple input buffers or that a string contains escape sequences.
/// To get a complete value in memory, you need to concatenate the values yourself.
/// Calling `nextAlloc*()` does this for you, and returns an `.allocated_*` token with the result.
///
/// For tokens with a `[]const u8` payload, the payload is a slice into the current input buffer.
/// The memory may become undefined during the next call to `json.Scanner.feedInput()`
/// or any `json.Reader` method whose return error set includes `json.Error`.
/// To keep the value persistently, it recommended to make a copy or to use `.alloc_always`,
/// which makes a copy for you.
///
/// Note that `.number` and `.string` tokens that follow `.partial_*` tokens may have `0` length to indicate that
/// the previously partial value is completed with no additional bytes.
/// (This can happen when the break between input buffers happens to land on the exact end of a value. E.g. `"[1234"`, `"]"`.)
/// `.partial_*` tokens never have `0` length.
///
/// The recommended strategy for using the different `next*()` methods is something like this:
///
/// When you're expecting an object key, use `.alloc_if_needed`.
/// You often don't need a copy of the key string to persist; you might just check which field it is.
/// In the case that the key happens to require an allocation, free it immediately after checking it.
///
/// When you're expecting a meaningful string value (such as on the right of a `:`),
/// use `.alloc_always` in order to keep the value valid throughout parsing the rest of the document.
///
/// When you're expecting a number value, use `.alloc_if_needed`.
/// You're probably going to be parsing the string representation of the number into a numeric representation,
/// so you need the complete string representation only temporarily.
///
/// When you're skipping an unrecognized value, use `skipValue()`.
pub const Token = union(enum) {
    object_begin,
    object_end,
    array_begin,
    array_end,

    true,
    false,
    null,

    number: []const u8,
    partial_number: []const u8,
    allocated_number: []u8,

    string: []const u8,
    partial_string: []const u8,
    partial_string_escaped_1: [1]u8,
    partial_string_escaped_2: [2]u8,
    partial_string_escaped_3: [3]u8,
    partial_string_escaped_4: [4]u8,
    allocated_string: []u8,

    end_of_document,
};

/// This is only used in `peekNextTokenType()` and gives a categorization based on the first byte of the next token that will be emitted from a `next*()` call.
pub const TokenType = enum {
    object_begin,
    object_end,
    array_begin,
    array_end,
    true,
    false,
    null,
    number,
    string,
    end_of_document,
};

/// To enable diagnostics, declare `var diagnostics = Diagnostics{};` then call `source.enableDiagnostics(&diagnostics);`
/// where `source` is either a `std.json.Reader` or a `std.json.Scanner` that has just been initialized.
/// At any time, notably just after an error, call `getLine()`, `getColumn()`, and/or `getByteOffset()`
/// to get meaningful information from this.
pub const Diagnostics = struct {
    line_number: u64 = 1,
    line_start_cursor: usize = @as(usize, @bitCast(@as(isize, -1))), // Start just "before" the input buffer to get a 1-based column for line 1.
    total_bytes_before_current_input: u64 = 0,
    cursor_pointer: *const usize = undefined,

    /// Starts at 1.
    pub fn getLine(self: *const @This()) u64 {
        return self.line_number;
    }
    /// Starts at 1.
    pub fn getColumn(self: *const @This()) u64 {
        return self.cursor_pointer.* -% self.line_start_cursor;
    }
    /// Starts at 0. Measures the byte offset since the start of the input.
    pub fn getByteOffset(self: *const @This()) u64 {
        return self.total_bytes_before_current_input + self.cursor_pointer.*;
    }
};

/// See the documentation for `std.json.Token`.
pub const AllocWhen = enum { alloc_if_needed, alloc_always };

/// For security, the maximum size allocated to store a single string or number value is limited to 4MiB by default.
/// This limit can be specified by calling `nextAllocMax()` instead of `nextAlloc()`.
pub const default_max_value_len = 4 * 1024 * 1024;

/// Connects a `std.io.Reader` to a `std.json.Scanner`.
/// All `next*()` methods here handle `error.BufferUnderrun` from `std.json.Scanner`, and then read from the reader.
pub fn Reader(comptime buffer_size: usize, comptime ReaderType: type) type {
    return struct {
        scanner: Scanner,
        reader: ReaderType,

        buffer: [buffer_size]u8 = undefined,

        /// The allocator is only used to track `[]` and `{}` nesting levels.
        pub fn init(allocator: Allocator, io_reader: ReaderType) @This() {
            return .{
                .scanner = Scanner.initStreaming(allocator),
                .reader = io_reader,
            };
        }
        pub fn deinit(self: *@This()) void {
            self.scanner.deinit();
            self.* = undefined;
        }

        /// Calls `std.json.Scanner.enableDiagnostics`.
        pub fn enableDiagnostics(self: *@This(), diagnostics: *Diagnostics) void {
            self.scanner.enableDiagnostics(diagnostics);
        }

        pub const NextError = ReaderType.Error || Error || Allocator.Error;
        pub const SkipError = NextError;
        pub const AllocError = NextError || error{ValueTooLong};
        pub const PeekError = ReaderType.Error || Error;

        /// Equivalent to `nextAllocMax(allocator, when, default_max_value_len);`
        /// See also `std.json.Token` for documentation of `nextAlloc*()` function behavior.
        pub fn nextAlloc(self: *@This(), allocator: Allocator, when: AllocWhen) AllocError!Token {
            return self.nextAllocMax(allocator, when, default_max_value_len);
        }
        /// See also `std.json.Token` for documentation of `nextAlloc*()` function behavior.
        pub fn nextAllocMax(self: *@This(), allocator: Allocator, when: AllocWhen, max_value_len: usize) AllocError!Token {
            const token_type = try self.peekNextTokenType();
            switch (token_type) {
                .number, .string => {
                    var value_list = ArrayList(u8).init(allocator);
                    errdefer {
                        value_list.deinit();
                    }
                    if (try self.allocNextIntoArrayListMax(&value_list, when, max_value_len)) |slice| {
                        return if (token_type == .number)
                            Token{ .number = slice }
                        else
                            Token{ .string = slice };
                    } else {
                        return if (token_type == .number)
                            Token{ .allocated_number = try value_list.toOwnedSlice() }
                        else
                            Token{ .allocated_string = try value_list.toOwnedSlice() };
                    }
                },

                // Simple tokens never alloc.
                .object_begin,
                .object_end,
                .array_begin,
                .array_end,
                .true,
                .false,
                .null,
                .end_of_document,
                => return try self.next(),
            }
        }

        /// Equivalent to `allocNextIntoArrayListMax(value_list, when, default_max_value_len);`
        pub fn allocNextIntoArrayList(self: *@This(), value_list: *ArrayList(u8), when: AllocWhen) AllocError!?[]const u8 {
            return self.allocNextIntoArrayListMax(value_list, when, default_max_value_len);
        }
        /// Calls `std.json.Scanner.allocNextIntoArrayListMax` and handles `error.BufferUnderrun`.
        pub fn allocNextIntoArrayListMax(self: *@This(), value_list: *ArrayList(u8), when: AllocWhen, max_value_len: usize) AllocError!?[]const u8 {
            while (true) {
                return self.scanner.allocNextIntoArrayListMax(value_list, when, max_value_len) catch |err| switch (err) {
                    error.BufferUnderrun => {
                        try self.refillBuffer();
                        continue;
                    },
                    else => |other_err| return other_err,
                };
            }
        }

        /// Like `std.json.Scanner.skipValue`, but handles `error.BufferUnderrun`.
        pub fn skipValue(self: *@This()) SkipError!void {
            switch (try self.peekNextTokenType()) {
                .object_begin, .array_begin => {
                    try self.skipUntilStackHeight(self.stackHeight());
                },
                .number, .string => {
                    while (true) {
                        switch (try self.next()) {
                            .partial_number,
                            .partial_string,
                            .partial_string_escaped_1,
                            .partial_string_escaped_2,
                            .partial_string_escaped_3,
                            .partial_string_escaped_4,
                            => continue,

                            .number, .string => break,

                            else => unreachable,
                        }
                    }
                },
                .true, .false, .null => {
                    _ = try self.next();
                },

                .object_end, .array_end, .end_of_document => unreachable, // Attempt to skip a non-value token.
            }
        }
        /// Like `std.json.Scanner.skipUntilStackHeight()` but handles `error.BufferUnderrun`.
        pub fn skipUntilStackHeight(self: *@This(), terminal_stack_height: usize) NextError!void {
            while (true) {
                return self.scanner.skipUntilStackHeight(terminal_stack_height) catch |err| switch (err) {
                    error.BufferUnderrun => {
                        try self.refillBuffer();
                        continue;
                    },
                    else => |other_err| return other_err,
                };
            }
        }

        /// Calls `std.json.Scanner.stackHeight`.
        pub fn stackHeight(self: *const @This()) usize {
            return self.scanner.stackHeight();
        }
        /// Calls `std.json.Scanner.ensureTotalStackCapacity`.
        pub fn ensureTotalStackCapacity(self: *@This(), height: usize) Allocator.Error!void {
            try self.scanner.ensureTotalStackCapacity(height);
        }

        /// See `std.json.Token` for documentation of this function.
        pub fn next(self: *@This()) NextError!Token {
            while (true) {
                return self.scanner.next() catch |err| switch (err) {
                    error.BufferUnderrun => {
                        try self.refillBuffer();
                        continue;
                    },
                    else => |other_err| return other_err,
                };
            }
        }

        /// See `std.json.Scanner.peekNextTokenType()`.
        pub fn peekNextTokenType(self: *@This()) PeekError!TokenType {
            while (true) {
                return self.scanner.peekNextTokenType() catch |err| switch (err) {
                    error.BufferUnderrun => {
                        try self.refillBuffer();
                        continue;
                    },
                    else => |other_err| return other_err,
                };
            }
        }

        fn refillBuffer(self: *@This()) ReaderType.Error!void {
            const input = self.buffer[0..try self.reader.read(self.buffer[0..])];
            if (input.len > 0) {
                self.scanner.feedInput(input);
            } else {
                self.scanner.endInput();
            }
        }
    };
}

/// The lowest level parsing API in this package;
/// supports streaming input with a low memory footprint.
/// The memory requirement is `O(d)` where d is the nesting depth of `[]` or `{}` containers in the input.
/// Specifically `d/8` bytes are required for this purpose,
/// with some extra buffer according to the implementation of `std.ArrayList`.
///
/// This scanner can emit partial tokens; see `std.json.Token`.
/// The input to this class is a sequence of input buffers that you must supply one at a time.
/// Call `feedInput()` with the first buffer, then call `next()` repeatedly until `error.BufferUnderrun` is returned.
/// Then call `feedInput()` again and so forth.
/// Call `endInput()` when the last input buffer has been given to `feedInput()`, either immediately after calling `feedInput()`,
/// or when `error.BufferUnderrun` requests more data and there is no more.
/// Be sure to call `next()` after calling `endInput()` until `Token.end_of_document` has been returned.
pub const Scanner = struct {
    state: State = .value,
    string_is_object_key: bool = false,
    stack: BitStack,
    value_start: usize = undefined,
    utf16_code_units: [2]u16 = undefined,

    input: []const u8 = "",
    cursor: usize = 0,
    is_end_of_input: bool = false,
    diagnostics: ?*Diagnostics = null,

    /// The allocator is only used to track `[]` and `{}` nesting levels.
    pub fn initStreaming(allocator: Allocator) @This() {
        return .{
            .stack = BitStack.init(allocator),
        };
    }
    /// Use this if your input is a single slice.
    /// This is effectively equivalent to:
    /// ```
    /// initStreaming(allocator);
    /// feedInput(complete_input);
    /// endInput();
    /// ```
    pub fn initCompleteInput(allocator: Allocator, complete_input: []const u8) @This() {
        return .{
            .stack = BitStack.init(allocator),
            .input = complete_input,
            .is_end_of_input = true,
        };
    }
    pub fn deinit(self: *@This()) void {
        self.stack.deinit();
        self.* = undefined;
    }

    pub fn enableDiagnostics(self: *@This(), diagnostics: *Diagnostics) void {
        diagnostics.cursor_pointer = &self.cursor;
        self.diagnostics = diagnostics;
    }

    /// Call this whenever you get `error.BufferUnderrun` from `next()`.
    /// When there is no more input to provide, call `endInput()`.
    pub fn feedInput(self: *@This(), input: []const u8) void {
        assert(self.cursor == self.input.len); // Not done with the last input slice.
        if (self.diagnostics) |diag| {
            diag.total_bytes_before_current_input += self.input.len;
            // This usually goes "negative" to measure how far before the beginning
            // of the new buffer the current line started.
            diag.line_start_cursor -%= self.cursor;
        }
        self.input = input;
        self.cursor = 0;
        self.value_start = 0;
    }
    /// Call this when you will no longer call `feedInput()` anymore.
    /// This can be called either immediately after the last `feedInput()`,
    /// or at any time afterward, such as when getting `error.BufferUnderrun` from `next()`.
    /// Don't forget to call `next*()` after `endInput()` until you get `.end_of_document`.
    pub fn endInput(self: *@This()) void {
        self.is_end_of_input = true;
    }

    pub const NextError = Error || Allocator.Error || error{BufferUnderrun};
    pub const AllocError = Error || Allocator.Error || error{ValueTooLong};
    pub const PeekError = Error || error{BufferUnderrun};
    pub const SkipError = Error || Allocator.Error;
    pub const AllocIntoArrayListError = AllocError || error{BufferUnderrun};

    /// Equivalent to `nextAllocMax(allocator, when, default_max_value_len);`
    /// This function is only available after `endInput()` (or `initCompleteInput()`) has been called.
    /// See also `std.json.Token` for documentation of `nextAlloc*()` function behavior.
    pub fn nextAlloc(self: *@This(), allocator: Allocator, when: AllocWhen) AllocError!Token {
        return self.nextAllocMax(allocator, when, default_max_value_len);
    }

    /// This function is only available after `endInput()` (or `initCompleteInput()`) has been called.
    /// See also `std.json.Token` for documentation of `nextAlloc*()` function behavior.
    pub fn nextAllocMax(self: *@This(), allocator: Allocator, when: AllocWhen, max_value_len: usize) AllocError!Token {
        assert(self.is_end_of_input); // This function is not available in streaming mode.
        const token_type = self.peekNextTokenType() catch |e| switch (e) {
            error.BufferUnderrun => unreachable,
            else => |err| return err,
        };
        switch (token_type) {
            .number, .string => {
                var value_list = ArrayList(u8).init(allocator);
                errdefer {
                    value_list.deinit();
                }
                if (self.allocNextIntoArrayListMax(&value_list, when, max_value_len) catch |e| switch (e) {
                    error.BufferUnderrun => unreachable,
                    else => |err| return err,
                }) |slice| {
                    return if (token_type == .number)
                        Token{ .number = slice }
                    else
                        Token{ .string = slice };
                } else {
                    return if (token_type == .number)
                        Token{ .allocated_number = try value_list.toOwnedSlice() }
                    else
                        Token{ .allocated_string = try value_list.toOwnedSlice() };
                }
            },

            // Simple tokens never alloc.
            .object_begin,
            .object_end,
            .array_begin,
            .array_end,
            .true,
            .false,
            .null,
            .end_of_document,
            => return self.next() catch |e| switch (e) {
                error.BufferUnderrun => unreachable,
                else => |err| return err,
            },
        }
    }

    /// Equivalent to `allocNextIntoArrayListMax(value_list, when, default_max_value_len);`
    pub fn allocNextIntoArrayList(self: *@This(), value_list: *ArrayList(u8), when: AllocWhen) AllocIntoArrayListError!?[]const u8 {
        return self.allocNextIntoArrayListMax(value_list, when, default_max_value_len);
    }
    /// The next token type must be either `.number` or `.string`. See `peekNextTokenType()`.
    /// When allocation is not necessary with `.alloc_if_needed`,
    /// this method returns the content slice from the input buffer, and `value_list` is not touched.
    /// When allocation is necessary or with `.alloc_always`, this method concatenates partial tokens into the given `value_list`,
    /// and returns `null` once the final `.number` or `.string` token has been written into it.
    /// In case of an `error.BufferUnderrun`, partial values will be left in the given value_list.
    /// The given `value_list` is never reset by this method, so an `error.BufferUnderrun` situation
    /// can be resumed by passing the same array list in again.
    /// This method does not indicate whether the token content being returned is for a `.number` or `.string` token type;
    /// the caller of this method is expected to know which type of token is being processed.
    pub fn allocNextIntoArrayListMax(self: *@This(), value_list: *ArrayList(u8), when: AllocWhen, max_value_len: usize) AllocIntoArrayListError!?[]const u8 {
        while (true) {
            const token = try self.next();
            switch (token) {
                // Accumulate partial values.
                .partial_number, .partial_string => |slice| {
                    try appendSlice(value_list, slice, max_value_len);
                },
                .partial_string_escaped_1 => |buf| {
                    try appendSlice(value_list, buf[0..], max_value_len);
                },
                .partial_string_escaped_2 => |buf| {
                    try appendSlice(value_list, buf[0..], max_value_len);
                },
                .partial_string_escaped_3 => |buf| {
                    try appendSlice(value_list, buf[0..], max_value_len);
                },
                .partial_string_escaped_4 => |buf| {
                    try appendSlice(value_list, buf[0..], max_value_len);
                },

                // Return complete values.
                .number => |slice| {
                    if (when == .alloc_if_needed and value_list.items.len == 0) {
                        // No alloc necessary.
                        return slice;
                    }
                    try appendSlice(value_list, slice, max_value_len);
                    // The token is complete.
                    return null;
                },
                .string => |slice| {
                    if (when == .alloc_if_needed and value_list.items.len == 0) {
                        // No alloc necessary.
                        return slice;
                    }
                    try appendSlice(value_list, slice, max_value_len);
                    // The token is complete.
                    return null;
                },

                .object_begin,
                .object_end,
                .array_begin,
                .array_end,
                .true,
                .false,
                .null,
                .end_of_document,
                => unreachable, // Only .number and .string token types are allowed here. Check peekNextTokenType() before calling this.

                .allocated_number, .allocated_string => unreachable,
            }
        }
    }

    /// This function is only available after `endInput()` (or `initCompleteInput()`) has been called.
    /// If the next token type is `.object_begin` or `.array_begin`,
    /// this function calls `next()` repeatedly until the corresponding `.object_end` or `.array_end` is found.
    /// If the next token type is `.number` or `.string`,
    /// this function calls `next()` repeatedly until the (non `.partial_*`) `.number` or `.string` token is found.
    /// If the next token type is `.true`, `.false`, or `.null`, this function calls `next()` once.
    /// The next token type must not be `.object_end`, `.array_end`, or `.end_of_document`;
    /// see `peekNextTokenType()`.
    pub fn skipValue(self: *@This()) SkipError!void {
        assert(self.is_end_of_input); // This function is not available in streaming mode.
        switch (self.peekNextTokenType() catch |e| switch (e) {
            error.BufferUnderrun => unreachable,
            else => |err| return err,
        }) {
            .object_begin, .array_begin => {
                self.skipUntilStackHeight(self.stackHeight()) catch |e| switch (e) {
                    error.BufferUnderrun => unreachable,
                    else => |err| return err,
                };
            },
            .number, .string => {
                while (true) {
                    switch (self.next() catch |e| switch (e) {
                        error.BufferUnderrun => unreachable,
                        else => |err| return err,
                    }) {
                        .partial_number,
                        .partial_string,
                        .partial_string_escaped_1,
                        .partial_string_escaped_2,
                        .partial_string_escaped_3,
                        .partial_string_escaped_4,
                        => continue,

                        .number, .string => break,

                        else => unreachable,
                    }
                }
            },
            .true, .false, .null => {
                _ = self.next() catch |e| switch (e) {
                    error.BufferUnderrun => unreachable,
                    else => |err| return err,
                };
            },

            .object_end, .array_end, .end_of_document => unreachable, // Attempt to skip a non-value token.
        }
    }

    /// Skip tokens until an `.object_end` or `.array_end` token results in a `stackHeight()` equal the given stack height.
    /// Unlike `skipValue()`, this function is available in streaming mode.
    pub fn skipUntilStackHeight(self: *@This(), terminal_stack_height: usize) NextError!void {
        while (true) {
            switch (try self.next()) {
                .object_end, .array_end => {
                    if (self.stackHeight() == terminal_stack_height) break;
                },
                .end_of_document => unreachable,
                else => continue,
            }
        }
    }

    /// The depth of `{}` or `[]` nesting levels at the current position.
    pub fn stackHeight(self: *const @This()) usize {
        return self.stack.bit_len;
    }

    /// Pre allocate memory to hold the given number of nesting levels.
    /// `stackHeight()` up to the given number will not cause allocations.
    pub fn ensureTotalStackCapacity(self: *@This(), height: usize) Allocator.Error!void {
        try self.stack.ensureTotalCapacity(height);
    }

    /// See `std.json.Token` for documentation of this function.
    pub fn next(self: *@This()) NextError!Token {
        state_loop: while (true) {
            switch (self.state) {
                .value => {
                    switch (try self.skipWhitespaceExpectByte()) {
                        // Object, Array
                        '{' => {
                            try self.stack.push(OBJECT_MODE);
                            self.cursor += 1;
                            self.state = .object_start;
                            return .object_begin;
                        },
                        '[' => {
                            try self.stack.push(ARRAY_MODE);
                            self.cursor += 1;
                            self.state = .array_start;
                            return .array_begin;
                        },

                        // String
                        '"' => {
                            self.cursor += 1;
                            self.value_start = self.cursor;
                            self.state = .string;
                            continue :state_loop;
                        },

                        // Number
                        '1'...'9' => {
                            self.value_start = self.cursor;
                            self.cursor += 1;
                            self.state = .number_int;
                            continue :state_loop;
                        },
                        '0' => {
                            self.value_start = self.cursor;
                            self.cursor += 1;
                            self.state = .number_leading_zero;
                            continue :state_loop;
                        },
                        '-' => {
                            self.value_start = self.cursor;
                            self.cursor += 1;
                            self.state = .number_minus;
                            continue :state_loop;
                        },

                        // literal values
                        't' => {
                            self.cursor += 1;
                            self.state = .literal_t;
                            continue :state_loop;
                        },
                        'f' => {
                            self.cursor += 1;
                            self.state = .literal_f;
                            continue :state_loop;
                        },
                        'n' => {
                            self.cursor += 1;
                            self.state = .literal_n;
                            continue :state_loop;
                        },

                        else => return error.SyntaxError,
                    }
                },

                .post_value => {
                    if (try self.skipWhitespaceCheckEnd()) return .end_of_document;

                    const c = self.input[self.cursor];
                    if (self.string_is_object_key) {
                        self.string_is_object_key = false;
                        switch (c) {
                            ':' => {
                                self.cursor += 1;
                                self.state = .value;
                                continue :state_loop;
                            },
                            else => return error.SyntaxError,
                        }
                    }

                    switch (c) {
                        '}' => {
                            if (self.stack.pop() != OBJECT_MODE) return error.SyntaxError;
                            self.cursor += 1;
                            // stay in .post_value state.
                            return .object_end;
                        },
                        ']' => {
                            if (self.stack.pop() != ARRAY_MODE) return error.SyntaxError;
                            self.cursor += 1;
                            // stay in .post_value state.
                            return .array_end;
                        },
                        ',' => {
                            switch (self.stack.peek()) {
                                OBJECT_MODE => {
                                    self.state = .object_post_comma;
                                },
                                ARRAY_MODE => {
                                    self.state = .value;
                                },
                            }
                            self.cursor += 1;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },

                .object_start => {
                    switch (try self.skipWhitespaceExpectByte()) {
                        '"' => {
                            self.cursor += 1;
                            self.value_start = self.cursor;
                            self.state = .string;
                            self.string_is_object_key = true;
                            continue :state_loop;
                        },
                        '}' => {
                            self.cursor += 1;
                            _ = self.stack.pop();
                            self.state = .post_value;
                            return .object_end;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .object_post_comma => {
                    switch (try self.skipWhitespaceExpectByte()) {
                        '"' => {
                            self.cursor += 1;
                            self.value_start = self.cursor;
                            self.state = .string;
                            self.string_is_object_key = true;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },

                .array_start => {
                    switch (try self.skipWhitespaceExpectByte()) {
                        ']' => {
                            self.cursor += 1;
                            _ = self.stack.pop();
                            self.state = .post_value;
                            return .array_end;
                        },
                        else => {
                            self.state = .value;
                            continue :state_loop;
                        },
                    }
                },

                .number_minus => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInNumber(false);
                    switch (self.input[self.cursor]) {
                        '0' => {
                            self.cursor += 1;
                            self.state = .number_leading_zero;
                            continue :state_loop;
                        },
                        '1'...'9' => {
                            self.cursor += 1;
                            self.state = .number_int;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .number_leading_zero => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInNumber(true);
                    switch (self.input[self.cursor]) {
                        '.' => {
                            self.cursor += 1;
                            self.state = .number_post_dot;
                            continue :state_loop;
                        },
                        'e', 'E' => {
                            self.cursor += 1;
                            self.state = .number_post_e;
                            continue :state_loop;
                        },
                        else => {
                            self.state = .post_value;
                            return Token{ .number = self.takeValueSlice() };
                        },
                    }
                },
                .number_int => {
                    while (self.cursor < self.input.len) : (self.cursor += 1) {
                        switch (self.input[self.cursor]) {
                            '0'...'9' => continue,
                            '.' => {
                                self.cursor += 1;
                                self.state = .number_post_dot;
                                continue :state_loop;
                            },
                            'e', 'E' => {
                                self.cursor += 1;
                                self.state = .number_post_e;
                                continue :state_loop;
                            },
                            else => {
                                self.state = .post_value;
                                return Token{ .number = self.takeValueSlice() };
                            },
                        }
                    }
                    return self.endOfBufferInNumber(true);
                },
                .number_post_dot => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInNumber(false);
                    switch (self.input[self.cursor]) {
                        '0'...'9' => {
                            self.cursor += 1;
                            self.state = .number_frac;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .number_frac => {
                    while (self.cursor < self.input.len) : (self.cursor += 1) {
                        switch (self.input[self.cursor]) {
                            '0'...'9' => continue,
                            'e', 'E' => {
                                self.cursor += 1;
                                self.state = .number_post_e;
                                continue :state_loop;
                            },
                            else => {
                                self.state = .post_value;
                                return Token{ .number = self.takeValueSlice() };
                            },
                        }
                    }
                    return self.endOfBufferInNumber(true);
                },
                .number_post_e => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInNumber(false);
                    switch (self.input[self.cursor]) {
                        '0'...'9' => {
                            self.cursor += 1;
                            self.state = .number_exp;
                            continue :state_loop;
                        },
                        '+', '-' => {
                            self.cursor += 1;
                            self.state = .number_post_e_sign;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .number_post_e_sign => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInNumber(false);
                    switch (self.input[self.cursor]) {
                        '0'...'9' => {
                            self.cursor += 1;
                            self.state = .number_exp;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .number_exp => {
                    while (self.cursor < self.input.len) : (self.cursor += 1) {
                        switch (self.input[self.cursor]) {
                            '0'...'9' => continue,
                            else => {
                                self.state = .post_value;
                                return Token{ .number = self.takeValueSlice() };
                            },
                        }
                    }
                    return self.endOfBufferInNumber(true);
                },

                .string => {
                    while (self.cursor < self.input.len) : (self.cursor += 1) {
                        switch (self.input[self.cursor]) {
                            0...0x1f => return error.SyntaxError, // Bare ASCII control code in string.

                            // ASCII plain text.
                            0x20...('"' - 1), ('"' + 1)...('\\' - 1), ('\\' + 1)...0x7F => continue,

                            // Special characters.
                            '"' => {
                                const result = Token{ .string = self.takeValueSlice() };
                                self.cursor += 1;
                                self.state = .post_value;
                                return result;
                            },
                            '\\' => {
                                const slice = self.takeValueSlice();
                                self.cursor += 1;
                                self.state = .string_backslash;
                                if (slice.len > 0) return Token{ .partial_string = slice };
                                continue :state_loop;
                            },

                            // UTF-8 validation.
                            // See http://unicode.org/mail-arch/unicode-ml/y2003-m02/att-0467/01-The_Algorithm_to_Valide_an_UTF-8_String
                            0xC2...0xDF => {
                                self.cursor += 1;
                                self.state = .string_utf8_last_byte;
                                continue :state_loop;
                            },
                            0xE0 => {
                                self.cursor += 1;
                                self.state = .string_utf8_second_to_last_byte_guard_against_overlong;
                                continue :state_loop;
                            },
                            0xE1...0xEC, 0xEE...0xEF => {
                                self.cursor += 1;
                                self.state = .string_utf8_second_to_last_byte;
                                continue :state_loop;
                            },
                            0xED => {
                                self.cursor += 1;
                                self.state = .string_utf8_second_to_last_byte_guard_against_surrogate_half;
                                continue :state_loop;
                            },
                            0xF0 => {
                                self.cursor += 1;
                                self.state = .string_utf8_third_to_last_byte_guard_against_overlong;
                                continue :state_loop;
                            },
                            0xF1...0xF3 => {
                                self.cursor += 1;
                                self.state = .string_utf8_third_to_last_byte;
                                continue :state_loop;
                            },
                            0xF4 => {
                                self.cursor += 1;
                                self.state = .string_utf8_third_to_last_byte_guard_against_too_large;
                                continue :state_loop;
                            },
                            0x80...0xC1, 0xF5...0xFF => return error.SyntaxError, // Invalid UTF-8.
                        }
                    }
                    if (self.is_end_of_input) return error.UnexpectedEndOfInput;
                    const slice = self.takeValueSlice();
                    if (slice.len > 0) return Token{ .partial_string = slice };
                    return error.BufferUnderrun;
                },
                .string_backslash => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    switch (self.input[self.cursor]) {
                        '"', '\\', '/' => {
                            // Since these characters now represent themselves literally,
                            // we can simply begin the next plaintext slice here.
                            self.value_start = self.cursor;
                            self.cursor += 1;
                            self.state = .string;
                            continue :state_loop;
                        },
                        'b' => {
                            self.cursor += 1;
                            self.value_start = self.cursor;
                            self.state = .string;
                            return Token{ .partial_string_escaped_1 = [_]u8{0x08} };
                        },
                        'f' => {
                            self.cursor += 1;
                            self.value_start = self.cursor;
                            self.state = .string;
                            return Token{ .partial_string_escaped_1 = [_]u8{0x0c} };
                        },
                        'n' => {
                            self.cursor += 1;
                            self.value_start = self.cursor;
                            self.state = .string;
                            return Token{ .partial_string_escaped_1 = [_]u8{'\n'} };
                        },
                        'r' => {
                            self.cursor += 1;
                            self.value_start = self.cursor;
                            self.state = .string;
                            return Token{ .partial_string_escaped_1 = [_]u8{'\r'} };
                        },
                        't' => {
                            self.cursor += 1;
                            self.value_start = self.cursor;
                            self.state = .string;
                            return Token{ .partial_string_escaped_1 = [_]u8{'\t'} };
                        },
                        'u' => {
                            self.cursor += 1;
                            self.state = .string_backslash_u;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .string_backslash_u => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    const c = self.input[self.cursor];
                    switch (c) {
                        '0'...'9' => {
                            self.utf16_code_units[0] = @as(u16, c - '0') << 12;
                        },
                        'A'...'F' => {
                            self.utf16_code_units[0] = @as(u16, c - 'A' + 10) << 12;
                        },
                        'a'...'f' => {
                            self.utf16_code_units[0] = @as(u16, c - 'a' + 10) << 12;
                        },
                        else => return error.SyntaxError,
                    }
                    self.cursor += 1;
                    self.state = .string_backslash_u_1;
                    continue :state_loop;
                },
                .string_backslash_u_1 => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    const c = self.input[self.cursor];
                    switch (c) {
                        '0'...'9' => {
                            self.utf16_code_units[0] |= @as(u16, c - '0') << 8;
                        },
                        'A'...'F' => {
                            self.utf16_code_units[0] |= @as(u16, c - 'A' + 10) << 8;
                        },
                        'a'...'f' => {
                            self.utf16_code_units[0] |= @as(u16, c - 'a' + 10) << 8;
                        },
                        else => return error.SyntaxError,
                    }
                    self.cursor += 1;
                    self.state = .string_backslash_u_2;
                    continue :state_loop;
                },
                .string_backslash_u_2 => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    const c = self.input[self.cursor];
                    switch (c) {
                        '0'...'9' => {
                            self.utf16_code_units[0] |= @as(u16, c - '0') << 4;
                        },
                        'A'...'F' => {
                            self.utf16_code_units[0] |= @as(u16, c - 'A' + 10) << 4;
                        },
                        'a'...'f' => {
                            self.utf16_code_units[0] |= @as(u16, c - 'a' + 10) << 4;
                        },
                        else => return error.SyntaxError,
                    }
                    self.cursor += 1;
                    self.state = .string_backslash_u_3;
                    continue :state_loop;
                },
                .string_backslash_u_3 => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    const c = self.input[self.cursor];
                    switch (c) {
                        '0'...'9' => {
                            self.utf16_code_units[0] |= c - '0';
                        },
                        'A'...'F' => {
                            self.utf16_code_units[0] |= c - 'A' + 10;
                        },
                        'a'...'f' => {
                            self.utf16_code_units[0] |= c - 'a' + 10;
                        },
                        else => return error.SyntaxError,
                    }
                    self.cursor += 1;
                    if (std.unicode.utf16IsHighSurrogate(self.utf16_code_units[0])) {
                        self.state = .string_surrogate_half;
                        continue :state_loop;
                    } else if (std.unicode.utf16IsLowSurrogate(self.utf16_code_units[0])) {
                        return error.SyntaxError; // Unexpected low surrogate half.
                    } else {
                        self.value_start = self.cursor;
                        self.state = .string;
                        return partialStringCodepoint(self.utf16_code_units[0]);
                    }
                },
                .string_surrogate_half => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    switch (self.input[self.cursor]) {
                        '\\' => {
                            self.cursor += 1;
                            self.state = .string_surrogate_half_backslash;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError, // Expected low surrogate half.
                    }
                },
                .string_surrogate_half_backslash => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    switch (self.input[self.cursor]) {
                        'u' => {
                            self.cursor += 1;
                            self.state = .string_surrogate_half_backslash_u;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError, // Expected low surrogate half.
                    }
                },
                .string_surrogate_half_backslash_u => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    switch (self.input[self.cursor]) {
                        'D', 'd' => {
                            self.cursor += 1;
                            self.utf16_code_units[1] = 0xD << 12;
                            self.state = .string_surrogate_half_backslash_u_1;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError, // Expected low surrogate half.
                    }
                },
                .string_surrogate_half_backslash_u_1 => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    const c = self.input[self.cursor];
                    switch (c) {
                        'C'...'F' => {
                            self.cursor += 1;
                            self.utf16_code_units[1] |= @as(u16, c - 'A' + 10) << 8;
                            self.state = .string_surrogate_half_backslash_u_2;
                            continue :state_loop;
                        },
                        'c'...'f' => {
                            self.cursor += 1;
                            self.utf16_code_units[1] |= @as(u16, c - 'a' + 10) << 8;
                            self.state = .string_surrogate_half_backslash_u_2;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError, // Expected low surrogate half.
                    }
                },
                .string_surrogate_half_backslash_u_2 => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    const c = self.input[self.cursor];
                    switch (c) {
                        '0'...'9' => {
                            self.cursor += 1;
                            self.utf16_code_units[1] |= @as(u16, c - '0') << 4;
                            self.state = .string_surrogate_half_backslash_u_3;
                            continue :state_loop;
                        },
                        'A'...'F' => {
                            self.cursor += 1;
                            self.utf16_code_units[1] |= @as(u16, c - 'A' + 10) << 4;
                            self.state = .string_surrogate_half_backslash_u_3;
                            continue :state_loop;
                        },
                        'a'...'f' => {
                            self.cursor += 1;
                            self.utf16_code_units[1] |= @as(u16, c - 'a' + 10) << 4;
                            self.state = .string_surrogate_half_backslash_u_3;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .string_surrogate_half_backslash_u_3 => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    const c = self.input[self.cursor];
                    switch (c) {
                        '0'...'9' => {
                            self.utf16_code_units[1] |= c - '0';
                        },
                        'A'...'F' => {
                            self.utf16_code_units[1] |= c - 'A' + 10;
                        },
                        'a'...'f' => {
                            self.utf16_code_units[1] |= c - 'a' + 10;
                        },
                        else => return error.SyntaxError,
                    }
                    self.cursor += 1;
                    self.value_start = self.cursor;
                    self.state = .string;
                    const code_point = std.unicode.utf16DecodeSurrogatePair(&self.utf16_code_units) catch unreachable;
                    return partialStringCodepoint(code_point);
                },

                .string_utf8_last_byte => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    switch (self.input[self.cursor]) {
                        0x80...0xBF => {
                            self.cursor += 1;
                            self.state = .string;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError, // Invalid UTF-8.
                    }
                },
                .string_utf8_second_to_last_byte => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    switch (self.input[self.cursor]) {
                        0x80...0xBF => {
                            self.cursor += 1;
                            self.state = .string_utf8_last_byte;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError, // Invalid UTF-8.
                    }
                },
                .string_utf8_second_to_last_byte_guard_against_overlong => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    switch (self.input[self.cursor]) {
                        0xA0...0xBF => {
                            self.cursor += 1;
                            self.state = .string_utf8_last_byte;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError, // Invalid UTF-8.
                    }
                },
                .string_utf8_second_to_last_byte_guard_against_surrogate_half => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    switch (self.input[self.cursor]) {
                        0x80...0x9F => {
                            self.cursor += 1;
                            self.state = .string_utf8_last_byte;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError, // Invalid UTF-8.
                    }
                },
                .string_utf8_third_to_last_byte => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    switch (self.input[self.cursor]) {
                        0x80...0xBF => {
                            self.cursor += 1;
                            self.state = .string_utf8_second_to_last_byte;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError, // Invalid UTF-8.
                    }
                },
                .string_utf8_third_to_last_byte_guard_against_overlong => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    switch (self.input[self.cursor]) {
                        0x90...0xBF => {
                            self.cursor += 1;
                            self.state = .string_utf8_second_to_last_byte;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError, // Invalid UTF-8.
                    }
                },
                .string_utf8_third_to_last_byte_guard_against_too_large => {
                    if (self.cursor >= self.input.len) return self.endOfBufferInString();
                    switch (self.input[self.cursor]) {
                        0x80...0x8F => {
                            self.cursor += 1;
                            self.state = .string_utf8_second_to_last_byte;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError, // Invalid UTF-8.
                    }
                },

                .literal_t => {
                    switch (try self.expectByte()) {
                        'r' => {
                            self.cursor += 1;
                            self.state = .literal_tr;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .literal_tr => {
                    switch (try self.expectByte()) {
                        'u' => {
                            self.cursor += 1;
                            self.state = .literal_tru;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .literal_tru => {
                    switch (try self.expectByte()) {
                        'e' => {
                            self.cursor += 1;
                            self.state = .post_value;
          ```
