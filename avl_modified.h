struct avl_node_s {
    struct avl_node_s *left;
    struct avl_node_s *right;
    int value;
};

typedef struct avl_node_s avl_node_t;
struct avl_tree_s {
    struct avl_node_s *root;
};

typedef struct avl_tree_s avl_tree_t;

extern avl_tree_t *avl_create();
void avl_insert( avl_tree_t *tree, int value );
avl_node_t *avl_find( avl_tree_t *tree, int value ); 
