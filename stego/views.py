import io
import base64
import json
import datetime

from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.views import View

from .forms import EncodeForm, DecodeForm
from .engine import encode_message, decode_message, get_image_capacity, is_password_protected


def index(request):
    return render(request, "stego/index.html")


# ─── Encode ──────────────────────────────────────────────────────────────────

class EncodeView(View):
    def get(self, request):
        return render(request, "stego/encode.html", {"form": EncodeForm()})

    def post(self, request):
        form    = EncodeForm(request.POST, request.FILES)
        context = {"form": form}

        if form.is_valid():
            img_file = form.cleaned_data["image"]
            message  = form.cleaned_data["message"]
            password = form.cleaned_data.get("password", "")

            try:
                image_bytes  = img_file.read()
                result_bytes = encode_message(image_bytes, message, password)

                b64 = base64.b64encode(result_bytes).decode("utf-8")
                context.update({
                    "success":        True,
                    "image_data_url": f"data:image/png;base64,{b64}",
                    "original_name":  img_file.name.rsplit(".", 1)[0] + "_stego.png",
                    "capacity":       get_image_capacity(image_bytes),
                    "message_len":    len(message.encode("utf-8")),
                    "password_used":  bool(password),
                })
            except ValueError as e:
                context["error"] = str(e)
            except Exception as e:
                context["error"] = f"Unexpected error: {e}"

        return render(request, "stego/encode.html", context)


# ─── Decode ──────────────────────────────────────────────────────────────────

class DecodeView(View):
    def get(self, request):
        return render(request, "stego/decode.html", {"form": DecodeForm()})

    def post(self, request):
        form    = DecodeForm(request.POST, request.FILES)
        context = {"form": form}

        if form.is_valid():
            img_file = form.cleaned_data["image"]
            password = form.cleaned_data.get("password", "")

            try:
                image_bytes = img_file.read()
                message     = decode_message(image_bytes, password)
                context.update({
                    "success":     True,
                    "message":     message,
                    "message_len": len(message),
                })
            except ValueError as e:
                err = str(e)
                if err.startswith("PASSWORD_REQUIRED"):
                    context["needs_password"] = True
                    context["error"] = "This image is password-protected. Enter the password below."
                elif err.startswith("WRONG_PASSWORD"):
                    context["needs_password"] = True
                    context["error"] = "Incorrect password. Please try again."
                else:
                    context["error"] = err
            except Exception as e:
                context["error"] = f"Unexpected error: {e}"

        return render(request, "stego/decode.html", context)


# ─── AJAX: check if image is password-protected ──────────────────────────────

class CheckLockView(View):
    def post(self, request):
        img_file = request.FILES.get("image")
        if not img_file:
            return JsonResponse({"error": "No image provided."}, status=400)
        try:
            locked = is_password_protected(img_file.read())
            return JsonResponse({"locked": locked})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)


# ─── AJAX: capacity ──────────────────────────────────────────────────────────

class CapacityView(View):
    def post(self, request):
        img_file = request.FILES.get("image")
        if not img_file:
            return JsonResponse({"error": "No image provided."}, status=400)
        try:
            return JsonResponse(get_image_capacity(img_file.read()))
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)


# ─── Export decoded message ──────────────────────────────────────────────────

class ExportTxtView(View):
    """Download the decoded message as a plain-text file."""
    def post(self, request):
        message = request.POST.get("message", "")
        if not message:
            return HttpResponse("No message provided.", status=400)

        ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"decoded_message_{ts}.txt"
        response = HttpResponse(message, content_type="text/plain; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


class ExportPdfView(View):
    """Download the decoded message as a styled PDF."""
    def post(self, request):
        message = request.POST.get("message", "")
        if not message:
            return HttpResponse("No message provided.", status=400)

        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, HRFlowable
            )
        except ImportError:
            return HttpResponse(
                "reportlab is not installed. Run: pip install reportlab",
                status=500,
            )

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=2.5 * cm, rightMargin=2.5 * cm,
            topMargin=2.5 * cm,  bottomMargin=2.5 * cm,
        )

        styles = getSampleStyleSheet()
        dark   = colors.HexColor("#090b0f")
        accent = colors.HexColor("#00e5a0")
        muted  = colors.HexColor("#5a6a80")

        title_style = ParagraphStyle(
            "StegoTitle",
            parent=styles["Title"],
            fontSize=22, textColor=dark, spaceAfter=4,
            fontName="Helvetica-Bold",
        )
        meta_style = ParagraphStyle(
            "StegoMeta",
            parent=styles["Normal"],
            fontSize=9, textColor=muted,
            fontName="Helvetica",
        )
        body_style = ParagraphStyle(
            "StegoBody",
            parent=styles["Normal"],
            fontSize=11, leading=18,
            textColor=dark, fontName="Courier",
            wordWrap="LTR",
        )

        ts    = datetime.datetime.now().strftime("%B %d, %Y at %H:%M:%S")
        story = [
            Paragraph("StegoVault — Decoded Message", title_style),
            Paragraph(f"Extracted on {ts}", meta_style),
            Spacer(1, 0.3 * cm),
            HRFlowable(width="100%", thickness=2, color=accent, spaceAfter=0.4 * cm),
        ]

        # Split message into paragraphs preserving line breaks
        for line in message.split("\n"):
            safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            story.append(Paragraph(safe if safe.strip() else "&nbsp;", body_style))
            story.append(Spacer(1, 0.05 * cm))

        story += [
            Spacer(1, 0.6 * cm),
            HRFlowable(width="100%", thickness=1, color=muted),
            Spacer(1, 0.2 * cm),
            Paragraph(
                f"Generated by StegoVault &mdash; {len(message):,} characters",
                meta_style,
            ),
        ]

        doc.build(story)
        buf.seek(0)

        ts_file  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"decoded_message_{ts_file}.pdf"
        response = HttpResponse(buf.read(), content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response
