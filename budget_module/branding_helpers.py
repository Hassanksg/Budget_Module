from flask import current_app
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors
from utils import get_mongo_db

# Updated Ficore color palette from style guide
FICORE_PRIMARY_COLOR = "#1E3A8A"  # Deep Blue
FICORE_HEADER_BG = "#FFF8F0"  # Soft Cream
FICORE_TEXT_COLOR = "#2E2E2E"  # Dark Gray
FICORE_LOGO_PATH = "img/ficore_logo.png"  # Relative to static folder
TOP_MARGIN = 10.5  # In inches
FICORE_MARKETING = "Empowering Africa's Households with Smart Budgeting. Contact: FicoreAfrica@gmail.com | +234-xxx-xxxx"
FICORE_BRAND = "Ficore Budget"

def draw_ficore_pdf_header(canvas, user, y_start=10.5):
    """
    Draw Ficore branding, user info, and Ficore Credits balance at the top of a PDF budget report.
    """
    inch = 72  # 1 inch in points
    static_folder = current_app.static_folder
    logo_path = f"{static_folder}/{FICORE_LOGO_PATH}"

    # Header dimensions
    header_height = 1.2  # Increased to accommodate Ficore Credits
    y_logo = y_start - 0.35
    y_brand = y_start - 0.1
    y_marketing = y_start - 0.25
    y_user = y_start - 0.65
    y_credits = y_start - 0.85  # New line for Ficore Credits balance
    y_separator = y_start - header_height + 0.05

    # Background rectangle for header
    canvas.setFillColor(FICORE_HEADER_BG)
    canvas.rect(
        0,
        y_separator * inch,
        8.5 * inch,
        (y_start - y_separator) * inch,
        fill=1,
        stroke=0
    )
    canvas.setFillColor(colors.black)  # Reset fill color

    # Draw logo
    try:
        logo = ImageReader(logo_path)
        canvas.drawImage(logo, 1 * inch, y_logo * inch, width=0.5 * inch, height=0.5 * inch, mask='auto')
    except Exception:
        pass  # Don't break PDF if logo fails

    # Brand name
    canvas.setFont("Helvetica-Bold", 16)
    canvas.setFillColor(FICORE_PRIMARY_COLOR)
    canvas.drawString(1.75 * inch, y_brand * inch, FICORE_BRAND)

    # Marketing
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(FICORE_TEXT_COLOR)
    canvas.drawString(1.75 * inch, y_marketing * inch, FICORE_MARKETING)

    # User info
    user_display = getattr(user, "display_name", "") or getattr(user, "_id", "") or getattr(user, "username", "User")
    user_email = getattr(user, "email", "")
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(FICORE_TEXT_COLOR)
    canvas.drawString(1 * inch, y_user * inch, f"Username: {user_display} | Email: {user_email}")

    # Ficore Credits balance
    db = get_mongo_db()
    user_data = db.users.find_one({'_id': user_display})
    credit_balance = int(user_data.get('ficore_credit_balance', 0)) if user_data else 0
    canvas.drawString(1 * inch, y_credits * inch, f"Ficore Credits: {credit_balance}")

    # Separator line (using Ficore Danger color #DC2626)
    canvas.setStrokeColor(colors.Color(220/255, 38/255, 38/255))  # Red #DC2626
    canvas.setLineWidth(1)
    canvas.line(0.7 * inch, y_separator * inch, 7.7 * inch, y_separator * inch)
    canvas.setStrokeColor(colors.black)  # Reset stroke color

def ficore_csv_header(user):
    """
    Return a list of rows for branding, user info, and Ficore Credits balance for CSV budget reports.
    """
    user_display = getattr(user, "display_name", "") or getattr(user, "_id", "") or getattr(user, "username", "User")
    user_email = getattr(user, "email", "")
    db = get_mongo_db()
    user_data = db.users.find_one({'_id': user_display})
    credit_balance = int(user_data.get('ficore_credit_balance', 0)) if user_data else 0
    return [
        [FICORE_BRAND],
        [FICORE_MARKETING],
        [f"Username: {user_display} | Email: {user_email}"],
        [f"Ficore Credits: {credit_balance}"],
        []

    ]
