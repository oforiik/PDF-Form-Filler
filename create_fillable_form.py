from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.pdfbase import pdfform
import os

def create_fillable_form():
    # Create the form PDF
    c = canvas.Canvas("form_template.pdf", pagesize=letter)
    
    # Set font and size
    c.setFont("Helvetica", 12)
    
    # Add a title
    c.drawString(50, 750, "Personal Information Form")
    
    # Create form fields
    form = c.acroForm
    
    # Define field positions
    fields = [
        ("Surname", 50, 700),
        ("Other Name(s)", 50, 650),
        ("Date of Birth", 50, 600),
        ("Gender", 50, 550),
        ("Email Address", 50, 500),
        ("Company Name Employed at", 50, 450),
        ("Nationality", 50, 400),
        ("Phone Number", 50, 350)
    ]
    
    # Add labels and fields
    for field_name, x, y in fields:
        # Add label
        c.drawString(x, y + 20, f"{field_name}:")
        
        # Add form field
        form.textfield(
            name=field_name,
            tooltip=f'Enter {field_name}',
            x=x + 150,
            y=y,
            width=300,
            height=20,
            borderStyle='solid',
            borderWidth=1
        )
    
    # Save the PDF
    c.save()
    print("Fillable PDF form created successfully!")

if __name__ == "__main__":
    create_fillable_form()
