import pandas as pd

# Read the Excel file
df = pd.read_excel('sample_data.xlsx')

# Print the column names and first few rows
print("Column names:")
print(df.columns.tolist())
print("\nFirst few rows:")
print(df.head())
