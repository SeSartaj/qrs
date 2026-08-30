"""Views for serving the React SPA."""
from django.http import HttpResponse
from django.views.decorators.http import require_GET


@require_GET
def index(request):
    """Serve the built SPA index.html."""
    from pathlib import Path

    index_path = Path(__file__).resolve().parent / "static" / "frontend" / "index.html"
    if not index_path.exists():
        return HttpResponse(
            "Frontend not built. Run `npm run build` in frontend/.",
            status=503,
            content_type="text/plain",
        )
    return HttpResponse(index_path.read_text(), content_type="text/html")