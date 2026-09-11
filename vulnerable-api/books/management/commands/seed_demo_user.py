"""
Tao tai khoan demo va them du lieu (don hang + danh gia) de dang nhap vao co ngay "Goi y cho ban".
Chay: python manage.py seed_demo_user
Dang nhap: username=demo, password=demo123
"""
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction

from books.models import Book, Order, OrderItem, Rating

User = get_user_model()

DEMO_USERNAME = "demo"
DEMO_PASSWORD = "demo123"


class Command(BaseCommand):
    help = "Tao user demo + don hang + danh gia de test goi y."

    def handle(self, *args, **options):
        books_with_category = Book.objects.filter(category__isnull=False).select_related("category")
        book_list = list(books_with_category)
        if len(book_list) < 5:
            self.stdout.write(
                self.style.WARNING("Can it nhat 5 sach co the loai. Chay: python manage.py seed_books")
            )
            return

        with transaction.atomic():
            user, created = User.objects.get_or_create(
                username=DEMO_USERNAME,
                defaults={"email": "demo@example.com", "is_staff": False, "is_active": True},
            )
            user.set_password(DEMO_PASSWORD)
            user.save()
            if created:
                self.stdout.write(f"Created user: {DEMO_USERNAME}")
            else:
                # Xoa du lieu cu de tao lai
                user.orders.all().delete()
                Rating.objects.filter(user=user).delete()
                self.stdout.write(f"Reset data for user: {DEMO_USERNAME}")

            # Don hang 1: 3 sach (nhieu the loai)
            order1 = Order.objects.create(user=user)
            for b in book_list[:3]:
                OrderItem.objects.create(order=order1, book=b, quantity=1, price=b.price)

            # Don hang 2: 2 sach khac
            order2 = Order.objects.create(user=user)
            for b in book_list[3:5]:
                OrderItem.objects.create(order=order2, book=b, quantity=1, price=b.price)

            # Danh gia 4-5 sao cho vai sach (the loai khac de goi y phong phu)
            for i, b in enumerate(book_list[5:9]):
                Rating.objects.update_or_create(
                    user=user,
                    book=b,
                    defaults={"score": 4 if i % 2 == 0 else 5, "comment": "Sach hay."},
                )

        self.stdout.write(
            self.style.SUCCESS(
                f"Done. Dang nhap: username={DEMO_USERNAME!r}, password={DEMO_PASSWORD!r}"
            )
        )
