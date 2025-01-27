#pragma once
#include <gromox/ab_tree.hpp>

extern BOOL ab_tree_fetch_node_properties(const gromox::ab_tree::ab_node&, const PROPTAG_ARRAY *tags, TPROPVAL_ARRAY *vals);
extern bool ab_tree_resolvename(const gromox::ab_tree::ab_base*, const char *str, std::vector<gromox::ab_tree::minid> &result);
extern BOOL ab_tree_match_minids(const gromox::ab_tree::ab_base *pbase, uint32_t container_id, const RESTRICTION *filter, LONG_ARRAY *minids);
