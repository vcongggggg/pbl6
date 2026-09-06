"""Context processor to inject cart_count and other global data into all templates."""


def cart_context(request):
    cart = request.session.get("cart")
    if not isinstance(cart, dict):
        cart = {}
    
    wishlist_count = 0
    wishlist_book_ids = []
    if request.user.is_authenticated:
        wishlist_qs = request.user.wishlist_items.values_list("book_id", flat=True)
        wishlist_count = wishlist_qs.count()
        wishlist_book_ids = list(wishlist_qs)
        
    return {
        "cart_count": sum(cart.values()) if cart else 0,
        "wishlist_count": wishlist_count,
        "wishlist_book_ids": wishlist_book_ids
    }
