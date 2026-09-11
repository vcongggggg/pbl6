import requests
from django.core.management.base import BaseCommand
from time import sleep

from books.category_utils import normalize_category_name
from books.models import Book, Category
from books.views import _sanitize_reader_html


def get_with_retries(url, timeout, retries):
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            last_error = exc
            if attempt < retries:
                sleep(1)
    raise last_error


class Command(BaseCommand):
    help = "Seeds digital books from Project Gutenberg"

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=10,
            help="So sach toi da can lay tu Gutendex.",
        )
        parser.add_argument(
            "--timeout",
            type=int,
            default=40,
            help="So giay cho moi request toi Gutendex/Project Gutenberg.",
        )
        parser.add_argument(
            "--retries",
            type=int,
            default=3,
            help="So lan thu lai khi API bi timeout hoac loi mang.",
        )
        parser.add_argument(
            "--update-existing",
            action="store_true",
            help="Cap nhat content_text/content_html/cover cho sach da ton tai.",
        )

    def handle(self, *args, **kwargs):
        limit = max(1, kwargs["limit"])
        timeout = max(5, kwargs["timeout"])
        retries = max(1, kwargs["retries"])
        update_existing = kwargs["update_existing"]

        self.stdout.write(self.style.SUCCESS("Dang bat dau keo sach tu Project Gutenberg..."))

        category, _ = Category.objects.get_or_create(name=normalize_category_name("Kinh điển"))
        api_url = "https://gutendex.com/books/?languages=en&topic=fiction"

        try:
            response = get_with_retries(api_url, timeout=timeout, retries=retries)
            data = response.json()
            books_data = data.get("results", [])[:limit]

            for b_data in books_data:
                title = b_data.get("title")
                author = b_data["authors"][0]["name"] if b_data["authors"] else "Unknown"
                gutenberg_id = b_data.get("id")

                self.stdout.write(f"Dang xu ly: {title}...")

                existing_book = Book.objects.filter(title=title, author=author).first()
                if existing_book and not update_existing:
                    self.stdout.write(self.style.WARNING(f"Sach '{title}' da ton tai. Bo qua."))
                    continue

                formats = b_data.get("formats", {})
                text_url = formats.get("text/plain; charset=utf-8") or formats.get("text/plain")
                html_url = (
                    formats.get("text/html; charset=utf-8")
                    or formats.get("text/html")
                    or formats.get("application/xhtml+xml")
                )

                if not text_url:
                    self.stdout.write(self.style.ERROR(f"Khong tim thay ban text cho {title}"))
                    continue

                try:
                    content_res = get_with_retries(text_url, timeout=timeout, retries=retries)
                    content_text = content_res.text
                    content_html = ""
                    if html_url:
                        try:
                            html_res = get_with_retries(html_url, timeout=timeout, retries=retries)
                            content_html = _sanitize_reader_html(html_res.text, base_url=html_url)
                        except requests.RequestException as e:
                            self.stdout.write(self.style.WARNING(f"Khong tai duoc HTML cho {title}: {str(e)}"))

                    cover_url = formats.get("image/jpeg")

                    defaults = {
                        "description": f"Một tác phẩm kinh điển từ Project Gutenberg (ID: {gutenberg_id}).",
                        "price": 89000,
                        "category": category,
                        "is_digital": True,
                        "content_text": content_text,
                        "content_html": content_html,
                        "cover_image": cover_url or "",
                        "stock": 30,
                    }
                    if existing_book:
                        for field, value in defaults.items():
                            setattr(existing_book, field, value)
                        existing_book.save()
                        self.stdout.write(self.style.SUCCESS(f"Da cap nhat thanh cong: {title}"))
                    else:
                        Book.objects.create(title=title, author=author, **defaults)
                        self.stdout.write(self.style.SUCCESS(f"Da them thanh cong: {title}"))

                except requests.RequestException as e:
                    self.stdout.write(self.style.ERROR(f"Loi khi tai noi dung {title}: {str(e)}"))

        except requests.RequestException as e:
            self.stdout.write(
                self.style.ERROR(
                    "Gutendex dang cham hoac loi mang. "
                    f"Hay thu lai sau, hoac tang --timeout. Chi tiet: {str(e)}"
                )
            )

        self.stdout.write(self.style.SUCCESS("--- Hoan tat qua trinh seed du lieu ---"))
