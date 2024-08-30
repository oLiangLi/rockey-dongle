#include "../base.h"

rLANG_DECLARE_MACHINE

namespace {
  template <int ii_>
  struct rlRBTNode_t {
    rlRBTNode_t(int ii) : index(ii), mask(rLANG_RBTREE_COLOR_MASK(ii)), unmask(rLANG_RBTREE_COLOR_UNMASK(ii)) {}

    void*& XDS_RBT_PARENT(void* node) { return rLANG_RBTREE_PARENT(node, index); }
    void*& XDS_RBT_LEFT_CHILD(void* node) { return rLANG_RBTREE_LEFT_CHILD(node, index); }
    void*& XDS_RBT_RIGHT_CHILD(void* node) { return rLANG_RBTREE_RIGHT_CHILD(node, index); }

    bool XDS_RBT_NODE_IS_RED(void* node) { return rLANG_RBTREE_IS_RED_(node, mask); }
    bool XDS_RBT_NODE_IS_BLACK(void* node) { return rLANG_RBTREE_IS_BLACK_(node, mask); }
    void XDS_RBT_NODE_SET_RED(void* node) { rLANG_RBTREE_SET_RED_(node, unmask); }
    void XDS_RBT_NODE_SET_BLACK(void* node) { rLANG_RBTREE_SET_BLACK_(node, mask); }

    void XDS_RBT_NODE_ASSI_CLR(void* node, void* rhs) { rLANG_RBTREE_ASSIGN_CLR_(node, rhs, mask); }
    void XDS_RBT_NODE_CLR_SWAP(void* node, void* rhs) { rLANG_RBTREE_CLR_SWAP_(node, rhs, mask); }

   private:
    const int index;
    const uintptr_t mask, unmask;
  };

  template <>
  struct rlRBTNode_t<0> {
    rlRBTNode_t(int ii) { assert(ii == 0); }

    void*& XDS_RBT_PARENT(void* node) { return rLANG_RBTREE_PARENT_0(node); }
    void*& XDS_RBT_LEFT_CHILD(void* node) { return rLANG_RBTREE_LEFT_CHILD_0(node); }
    void*& XDS_RBT_RIGHT_CHILD(void* node) { return rLANG_RBTREE_RIGHT_CHILD_0(node); }

    bool XDS_RBT_NODE_IS_RED(void* node) { return rLANG_RBTREE_IS_RED_0(node); }
    bool XDS_RBT_NODE_IS_BLACK(void* node) { return rLANG_RBTREE_IS_BLACK_0(node); }
    void XDS_RBT_NODE_SET_RED(void* node) { rLANG_RBTREE_SET_RED_(node, rLANG_RBTREE_COLOR_UNMASK(0)); }
    void XDS_RBT_NODE_SET_BLACK(void* node) { rLANG_RBTREE_SET_BLACK_(node, rLANG_RBTREE_COLOR_MASK(0)); }

    void XDS_RBT_NODE_ASSI_CLR(void* node, void* rhs) {
      rLANG_RBTREE_ASSIGN_CLR_(node, rhs, rLANG_RBTREE_COLOR_MASK(0));
    }
    void XDS_RBT_NODE_CLR_SWAP(void* node, void* rhs) { rLANG_RBTREE_CLR_SWAP_(node, rhs, rLANG_RBTREE_COLOR_MASK(0)); }
  };

  template <>
  struct rlRBTNode_t<1> {
    rlRBTNode_t(int ii) { assert(ii == 1); }

    void*& XDS_RBT_PARENT(void* node) { return rLANG_RBTREE_PARENT_1(node); }
    void*& XDS_RBT_LEFT_CHILD(void* node) { return rLANG_RBTREE_LEFT_CHILD_1(node); }
    void*& XDS_RBT_RIGHT_CHILD(void* node) { return rLANG_RBTREE_RIGHT_CHILD_1(node); }

    bool XDS_RBT_NODE_IS_RED(void* node) { return rLANG_RBTREE_IS_RED_1(node); }
    bool XDS_RBT_NODE_IS_BLACK(void* node) { return rLANG_RBTREE_IS_BLACK_1(node); }
    void XDS_RBT_NODE_SET_RED(void* node) { rLANG_RBTREE_SET_RED_(node, rLANG_RBTREE_COLOR_UNMASK(1)); }
    void XDS_RBT_NODE_SET_BLACK(void* node) { rLANG_RBTREE_SET_BLACK_(node, rLANG_RBTREE_COLOR_MASK(1)); }

    void XDS_RBT_NODE_ASSI_CLR(void* node, void* rhs) {
      rLANG_RBTREE_ASSIGN_CLR_(node, rhs, rLANG_RBTREE_COLOR_MASK(1));
    }
    void XDS_RBT_NODE_CLR_SWAP(void* node, void* rhs) { rLANG_RBTREE_CLR_SWAP_(node, rhs, rLANG_RBTREE_COLOR_MASK(1)); }
  };

  template <typename Base>
  struct rlRBTree_t : public Base {
    rlRBTree_t(int ii) : Base(ii) {}

    using Base::XDS_RBT_LEFT_CHILD;
    using Base::XDS_RBT_NODE_ASSI_CLR;
    using Base::XDS_RBT_NODE_CLR_SWAP;
    using Base::XDS_RBT_NODE_IS_BLACK;
    using Base::XDS_RBT_NODE_IS_RED;
    using Base::XDS_RBT_NODE_SET_BLACK;
    using Base::XDS_RBT_NODE_SET_RED;
    using Base::XDS_RBT_PARENT;
    using Base::XDS_RBT_RIGHT_CHILD;

    void XDS_RBT_ROTATE_LEFT(void* node, void** root) {
      void* yy = XDS_RBT_RIGHT_CHILD(node);
      XDS_RBT_RIGHT_CHILD(node) = XDS_RBT_LEFT_CHILD(yy);
      if (XDS_RBT_LEFT_CHILD(yy))
        XDS_RBT_PARENT(XDS_RBT_LEFT_CHILD(yy)) = node;
      XDS_RBT_PARENT(yy) = XDS_RBT_PARENT(node);

      if (node == *root)
        *root = yy;
      else if (node == XDS_RBT_LEFT_CHILD(XDS_RBT_PARENT(node)))
        XDS_RBT_LEFT_CHILD(XDS_RBT_PARENT(node)) = yy;
      else
        XDS_RBT_RIGHT_CHILD(XDS_RBT_PARENT(node)) = yy;
      XDS_RBT_LEFT_CHILD(yy) = node;
      XDS_RBT_PARENT(node) = yy;
    }

    void XDS_RBT_ROTATE_RIGHT(void* node, void** root) {
      void* yy = XDS_RBT_LEFT_CHILD(node);
      XDS_RBT_LEFT_CHILD(node) = XDS_RBT_RIGHT_CHILD(yy);
      if (XDS_RBT_RIGHT_CHILD(yy))
        XDS_RBT_PARENT(XDS_RBT_RIGHT_CHILD(yy)) = node;
      XDS_RBT_PARENT(yy) = XDS_RBT_PARENT(node);

      if (node == *root)
        *root = yy;
      else if (node == XDS_RBT_RIGHT_CHILD(XDS_RBT_PARENT(node)))
        XDS_RBT_RIGHT_CHILD(XDS_RBT_PARENT(node)) = yy;
      else
        XDS_RBT_LEFT_CHILD(XDS_RBT_PARENT(node)) = yy;
      XDS_RBT_RIGHT_CHILD(yy) = node;
      XDS_RBT_PARENT(node) = yy;
    }

    void XDS_RBT_INSERT_NODE(void* xx, void** root) {
      XDS_RBT_NODE_SET_RED(xx);
      while (xx != *root && XDS_RBT_NODE_IS_RED(XDS_RBT_PARENT(xx))) {
        if (XDS_RBT_PARENT(xx) == XDS_RBT_LEFT_CHILD(XDS_RBT_PARENT(XDS_RBT_PARENT(xx)))) {
          void* yy = XDS_RBT_RIGHT_CHILD(XDS_RBT_PARENT(XDS_RBT_PARENT(xx)));
          if (yy && XDS_RBT_NODE_IS_RED(yy)) {
            XDS_RBT_NODE_SET_BLACK(XDS_RBT_PARENT(xx));
            XDS_RBT_NODE_SET_BLACK(yy);
            XDS_RBT_NODE_SET_RED(XDS_RBT_PARENT(XDS_RBT_PARENT(xx)));
            xx = XDS_RBT_PARENT(XDS_RBT_PARENT(xx));
          } else {
            if (xx == XDS_RBT_RIGHT_CHILD(XDS_RBT_PARENT(xx))) {
              xx = XDS_RBT_PARENT(xx);
              XDS_RBT_ROTATE_LEFT(xx, root);
            }
            XDS_RBT_NODE_SET_BLACK(XDS_RBT_PARENT(xx));
            XDS_RBT_NODE_SET_RED(XDS_RBT_PARENT(XDS_RBT_PARENT(xx)));
            XDS_RBT_ROTATE_RIGHT(XDS_RBT_PARENT(XDS_RBT_PARENT(xx)), root);
          }
        } else {
          void* yy = XDS_RBT_LEFT_CHILD(XDS_RBT_PARENT(XDS_RBT_PARENT(xx)));
          if (yy && XDS_RBT_NODE_IS_RED(yy)) {
            XDS_RBT_NODE_SET_BLACK(XDS_RBT_PARENT(xx));
            XDS_RBT_NODE_SET_BLACK(yy);
            XDS_RBT_NODE_SET_RED(XDS_RBT_PARENT(XDS_RBT_PARENT(xx)));
            xx = XDS_RBT_PARENT(XDS_RBT_PARENT(xx));
          } else {
            if (xx == XDS_RBT_LEFT_CHILD(XDS_RBT_PARENT(xx))) {
              xx = XDS_RBT_PARENT(xx);
              XDS_RBT_ROTATE_RIGHT(xx, root);
            }
            XDS_RBT_NODE_SET_BLACK(XDS_RBT_PARENT(xx));
            XDS_RBT_NODE_SET_RED(XDS_RBT_PARENT(XDS_RBT_PARENT(xx)));
            XDS_RBT_ROTATE_LEFT(XDS_RBT_PARENT(XDS_RBT_PARENT(xx)), root);
          }
        }
      }
      XDS_RBT_NODE_SET_BLACK(*root);
    }

    void XDS_RBT_ERASE_NODE(void* zz, void** root) {
      void *yy = zz, *xx = nullptr, *xxp = nullptr;

      if (XDS_RBT_LEFT_CHILD(yy) == nullptr)
        xx = XDS_RBT_RIGHT_CHILD(yy);
      else if (XDS_RBT_RIGHT_CHILD(yy) == nullptr)
        xx = XDS_RBT_LEFT_CHILD(yy);
      else {
        yy = XDS_RBT_RIGHT_CHILD(yy);
        while (XDS_RBT_LEFT_CHILD(yy) != nullptr)
          yy = XDS_RBT_LEFT_CHILD(yy);
        xx = XDS_RBT_RIGHT_CHILD(yy);
      }

      if (yy != zz) {
        XDS_RBT_PARENT(XDS_RBT_LEFT_CHILD(zz)) = yy;
        XDS_RBT_LEFT_CHILD(yy) = XDS_RBT_LEFT_CHILD(zz);
        if (yy != XDS_RBT_RIGHT_CHILD(zz)) {
          xxp = XDS_RBT_PARENT(yy);
          if (xx)
            XDS_RBT_PARENT(xx) = XDS_RBT_PARENT(yy);
          XDS_RBT_LEFT_CHILD(XDS_RBT_PARENT(yy)) = xx;
          XDS_RBT_RIGHT_CHILD(yy) = XDS_RBT_RIGHT_CHILD(zz);
          XDS_RBT_PARENT(XDS_RBT_RIGHT_CHILD(zz)) = yy;
        } else
          xxp = yy;
        if (*root == zz)
          *root = yy;
        else if (XDS_RBT_LEFT_CHILD(XDS_RBT_PARENT(zz)) == zz)
          XDS_RBT_LEFT_CHILD(XDS_RBT_PARENT(zz)) = yy;
        else
          XDS_RBT_RIGHT_CHILD(XDS_RBT_PARENT(zz)) = yy;
        XDS_RBT_PARENT(yy) = XDS_RBT_PARENT(zz);
        XDS_RBT_NODE_CLR_SWAP(yy, zz);
        yy = zz;
      } else {
        xxp = XDS_RBT_PARENT(yy);
        if (xx)
          XDS_RBT_PARENT(xx) = XDS_RBT_PARENT(yy);
        if (*root == zz)
          *root = xx;
        else if (XDS_RBT_LEFT_CHILD(XDS_RBT_PARENT(zz)) == zz)
          XDS_RBT_LEFT_CHILD(XDS_RBT_PARENT(zz)) = xx;
        else
          XDS_RBT_RIGHT_CHILD(XDS_RBT_PARENT(zz)) = xx;
      }
      if (XDS_RBT_NODE_IS_BLACK(yy)) {
        while (xx != *root && (xx == nullptr || XDS_RBT_NODE_IS_BLACK(xx))) {
          if (xx == XDS_RBT_LEFT_CHILD(xxp)) {
            void* ww = XDS_RBT_RIGHT_CHILD(xxp);
            if (XDS_RBT_NODE_IS_RED(ww)) {
              XDS_RBT_NODE_SET_BLACK(ww);
              XDS_RBT_NODE_SET_RED(xxp);
              XDS_RBT_ROTATE_LEFT(xxp, root);
              ww = XDS_RBT_RIGHT_CHILD(xxp);
            }
            if ((XDS_RBT_LEFT_CHILD(ww) == nullptr || XDS_RBT_NODE_IS_BLACK(XDS_RBT_LEFT_CHILD(ww))) &&
                (XDS_RBT_RIGHT_CHILD(ww) == nullptr || XDS_RBT_NODE_IS_BLACK(XDS_RBT_RIGHT_CHILD(ww)))) {
              XDS_RBT_NODE_SET_RED(ww);
              xx = xxp;
              xxp = XDS_RBT_PARENT(xxp);
            } else {
              if (XDS_RBT_RIGHT_CHILD(ww) == nullptr || XDS_RBT_NODE_IS_BLACK(XDS_RBT_RIGHT_CHILD(ww))) {
                XDS_RBT_NODE_SET_BLACK(XDS_RBT_LEFT_CHILD(ww));
                XDS_RBT_NODE_SET_RED(ww);
                XDS_RBT_ROTATE_RIGHT(ww, root);
                ww = XDS_RBT_RIGHT_CHILD(xxp);
              }

              XDS_RBT_NODE_ASSI_CLR(ww, xxp);
              XDS_RBT_NODE_SET_BLACK(xxp);
              if (XDS_RBT_RIGHT_CHILD(ww))
                XDS_RBT_NODE_SET_BLACK(XDS_RBT_RIGHT_CHILD(ww));
              XDS_RBT_ROTATE_LEFT(xxp, root);
              break;
            }
          } else {
            void* ww = XDS_RBT_LEFT_CHILD(xxp);
            if (XDS_RBT_NODE_IS_RED(ww)) {
              XDS_RBT_NODE_SET_BLACK(ww);
              XDS_RBT_NODE_SET_RED(xxp);
              XDS_RBT_ROTATE_RIGHT(xxp, root);
              ww = XDS_RBT_LEFT_CHILD(xxp);
            }
            if ((XDS_RBT_RIGHT_CHILD(ww) == nullptr || XDS_RBT_NODE_IS_BLACK(XDS_RBT_RIGHT_CHILD(ww))) &&
                (XDS_RBT_LEFT_CHILD(ww) == nullptr || XDS_RBT_NODE_IS_BLACK(XDS_RBT_LEFT_CHILD(ww)))) {
              XDS_RBT_NODE_SET_RED(ww);
              xx = xxp;
              xxp = XDS_RBT_PARENT(xxp);
            } else {
              if (XDS_RBT_LEFT_CHILD(ww) == nullptr || XDS_RBT_NODE_IS_BLACK(XDS_RBT_LEFT_CHILD(ww))) {
                XDS_RBT_NODE_SET_BLACK(XDS_RBT_RIGHT_CHILD(ww));
                XDS_RBT_NODE_SET_RED(ww);
                XDS_RBT_ROTATE_LEFT(ww, root);
                ww = XDS_RBT_LEFT_CHILD(xxp);
              }
              XDS_RBT_NODE_ASSI_CLR(ww, xxp);
              XDS_RBT_NODE_SET_BLACK(xxp);
              if (XDS_RBT_LEFT_CHILD(ww))
                XDS_RBT_NODE_SET_BLACK(XDS_RBT_LEFT_CHILD(ww));
              XDS_RBT_ROTATE_RIGHT(xxp, root);
              break;
            }
          }
        }
        if (xx)
          XDS_RBT_NODE_SET_BLACK(xx);
      }
    }
  };
}


rLANGEXPORT void rLANGAPI rLANG_RBTREE_INSERT_NODE_0(void* node, void** root) {
  rlRBTree_t<rlRBTNode_t<0>>(0).XDS_RBT_INSERT_NODE(node, root);
}

rLANGEXPORT void rLANGAPI rLANG_RBTREE_INSERT_NODE_1(void* node, void** root) {
  rlRBTree_t<rlRBTNode_t<1>>(1).XDS_RBT_INSERT_NODE(node, root);
}
rLANGEXPORT void rLANGAPI rLANG_RBTREE_INSERT_NODE_X(void* node, void** root, const int index) {
  assert(index >= 0 && index < (int)(sizeof(uintptr_t) * CHAR_BIT));

  if (index <= 1) {
    if (1 == index)
      rLANG_RBTREE_INSERT_NODE_1(node, root);
    else
      rLANG_RBTREE_INSERT_NODE_0(node, root);
  } else {
    rlRBTree_t<rlRBTNode_t<-1>>(index).XDS_RBT_INSERT_NODE(node, root);
  }
}

rLANGEXPORT void rLANGAPI rLANG_RBTREE_ERASE_NODE_0(void* node, void** root) {
  rlRBTree_t<rlRBTNode_t<0>>(0).XDS_RBT_ERASE_NODE(node, root);
}
rLANGEXPORT void rLANGAPI rLANG_RBTREE_ERASE_NODE_1(void* node, void** root) {
  rlRBTree_t<rlRBTNode_t<1>>(1).XDS_RBT_ERASE_NODE(node, root);
}
rLANGEXPORT void rLANGAPI rLANG_RBTREE_ERASE_NODE_X(void* node, void** root, const int index) {
  assert(index >= 0 && index < (int)(sizeof(uintptr_t) * CHAR_BIT));

  if (index <= 1) {
    if (1 == index)
      rLANG_RBTREE_ERASE_NODE_1(node, root);
    else
      rLANG_RBTREE_ERASE_NODE_0(node, root);
  } else {
    rlRBTree_t<rlRBTNode_t<-1>>(index).XDS_RBT_ERASE_NODE(node, root);
  }
}

rLANG_DECLARE_END
