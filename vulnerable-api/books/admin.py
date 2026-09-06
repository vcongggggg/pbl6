from django.contrib import admin

from .models import AdminAuditLog, Book, Category, Coupon, Order, OrderItem, Rating, Wishlist


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ("name", "book_count")
    search_fields = ("name",)

    def book_count(self, obj):
        return obj.books.count()
    book_count.short_description = "Số sách"


class OrderItemInline(admin.TabularInline):
    model = OrderItem
    extra = 0
    raw_id_fields = ("book",)


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "status", "created_at", "item_count", "total_amount")
    list_filter = ("status", "created_at")
    list_editable = ("status",)
    search_fields = ("user__username",)
    inlines = (OrderItemInline,)

    def item_count(self, obj):
        return obj.items.count()
    item_count.short_description = "Số mục"

    def total_amount(self, obj):
        return f"{obj.total:,.0f}₫"
    total_amount.short_description = "Tổng tiền"


@admin.register(Book)
class BookAdmin(admin.ModelAdmin):
    list_display = ("title", "author", "category", "price", "stock", "published_year", "created_at")
    list_filter = ("category",)
    search_fields = ("title", "author")
    list_editable = ("price", "stock")


@admin.register(Wishlist)
class WishlistAdmin(admin.ModelAdmin):
    list_display = ("user", "book", "added_at")
    list_filter = ("added_at",)
    raw_id_fields = ("user", "book")


@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    list_display = ("order", "book", "quantity", "price", "subtotal_display")
    list_filter = ("order",)
    raw_id_fields = ("order", "book")

    def subtotal_display(self, obj):
        return f"{obj.subtotal:,.0f}₫"
    subtotal_display.short_description = "Thành tiền"


@admin.register(Rating)
class RatingAdmin(admin.ModelAdmin):
    list_display = ("user", "book", "score", "created_at")
    list_filter = ("score",)
    search_fields = ("user__username", "book__title")


@admin.register(Coupon)
class CouponAdmin(admin.ModelAdmin):
    list_display = ("code", "discount_type", "discount_value", "used_count", "max_uses", "active", "valid_from", "valid_to")
    list_filter = ("active", "discount_type")
    list_editable = ("active",)
    search_fields = ("code",)


@admin.register(AdminAuditLog)
class AdminAuditLogAdmin(admin.ModelAdmin):
    list_display = ("action", "actor", "target_type", "target_id", "created_at")
    list_filter = ("action", "target_type")
    search_fields = ("action", "target_type", "target_id", "actor__username")
