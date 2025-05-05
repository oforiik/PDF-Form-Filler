import pandas as pd
from faker import Faker
import random
from datetime import datetime, timedelta

# Initialize Faker
fake = Faker()

# Generate 30 random records
data = []
for _ in range(30):
    # Generate random date of birth (between 25 and 60 years ago)
    dob = fake.date_of_birth(minimum_age=25, maximum_age=60)
    
    data.append({
        'Surname': fake.last_name(),
        'Other Name(s)': f"{fake.first_name()} {fake.first_name() if random.random() > 0.5 else ''}".strip(),
        'Date of Birth': dob.strftime('%Y-%m-%d'),
        'Gender': random.choice(['Male', 'Female']),
        'Email Address': 'oforikevin13@gmail.com',  # Fixed email for testing
        'Company Name Employed at': fake.company(),
        'Nationality': fake.country(),
        'Phone Number': fake.phone_number()
    })

# Create DataFrame
df = pd.DataFrame(data)

# Save to Excel
output_file = 'sample_data.xlsx'
df.to_excel(output_file, index=False)
print(f"Generated {output_file} with {len(data)} random records.")
