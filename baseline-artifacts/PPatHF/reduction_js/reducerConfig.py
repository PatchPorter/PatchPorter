# change this to your tree-sitter path
tree_sitter_project_path = "./tree-sitter-javascript-0.23.1/"
tree_sitter_lib_path = tree_sitter_project_path + "/build/tree-sitter-js-lib.so"

enough_alpha_threshold = 5

reducing_log_path = "logs/reduce.log"
reducing_output_path = "output/"
reducing_input_file = "dataset/baseline_ppathf.json"

basic_unit_type = {
    "if_statement",
    "else_clause",
    "switch_statement",
    "case_statement",
    "for_statement",
    "while_statement",
    "do_statement",
    "for_in_statement",
    "for_of_statement",
    "try_statement",
    "catch_clause",
    "finally_clause",
}

levenshtein_similarity_threshold_weak = 0.5
levenshtein_similarity_threshold_parent = 0.55
levenshtein_similarity_threshold_ancestors = 0.45
length_ratio_threshold = 2.5

assert length_ratio_threshold >= 1, "length_ratio_threshold must be greater than or equal to 1!"