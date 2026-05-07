from django import forms

ALLOWED_TYPES = ["image/png", "image/bmp", "image/jpeg", "image/jpg"]


class EncodeForm(forms.Form):
    image = forms.ImageField(
        label="Carrier Image",
        help_text="PNG or BMP recommended. Max 10 MB.",
        widget=forms.ClearableFileInput(
            attrs={"accept": "image/png,image/bmp,image/jpeg"}
        ),
    )
    message = forms.CharField(
        label="Secret Message",
        widget=forms.Textarea(
            attrs={"rows": 5, "placeholder": "Type your secret message here..."}
        ),
        max_length=500_000,
    )
    password = forms.CharField(
        label="Password (optional)",
        required=False,
        max_length=256,
        widget=forms.PasswordInput(
            attrs={"placeholder": "Leave blank for no encryption", "autocomplete": "new-password"}
        ),
        help_text="If set, the message will be AES-256 encrypted inside the image.",
    )
    password_confirm = forms.CharField(
        label="Confirm Password",
        required=False,
        max_length=256,
        widget=forms.PasswordInput(
            attrs={"placeholder": "Repeat password", "autocomplete": "new-password"}
        ),
    )

    def clean_image(self):
        img = self.cleaned_data.get("image")
        if img:
            if img.content_type not in ALLOWED_TYPES:
                raise forms.ValidationError("Only PNG, BMP, and JPEG images are supported.")
            if img.size > 10 * 1024 * 1024:
                raise forms.ValidationError("Image must be under 10 MB.")
        return img

    def clean(self):
        cleaned = super().clean()
        pw  = cleaned.get("password", "")
        pw2 = cleaned.get("password_confirm", "")
        if pw and pw != pw2:
            self.add_error("password_confirm", "Passwords do not match.")
        return cleaned


class DecodeForm(forms.Form):
    image = forms.ImageField(
        label="Stego Image",
        help_text="Upload the image that contains a hidden message.",
        widget=forms.ClearableFileInput(attrs={"accept": "image/*"}),
    )
    password = forms.CharField(
        label="Password",
        required=False,
        max_length=256,
        widget=forms.PasswordInput(
            attrs={"placeholder": "Enter password if image is locked", "autocomplete": "current-password"}
        ),
    )

    def clean_image(self):
        img = self.cleaned_data.get("image")
        if img and img.size > 10 * 1024 * 1024:
            raise forms.ValidationError("Image must be under 10 MB.")
        return img
