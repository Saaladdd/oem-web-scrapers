from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup


chromedriver_path = r'C:\webriver\chromedriver-win64\chromedriver.exe'

service = Service(chromedriver_path)

driver = webdriver.Chrome(service=service)


driver.get("https://access.redhat.com/security/security-updates/cve")


WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "cp-tbody")))


html_content = driver.page_source


soup = BeautifulSoup(html_content, 'html.parser')


table_rows = soup.find_all('cp-tr', role='row')
cve_list = []

if table_rows:
    for row in table_rows:
        cve = row.find('cp-th', scope='row')
        description = row.find('cp-td', {'data-label': 'Description'})
        severity = row.find('cp-td', {'data-label': 'CVE Severity'})
        publish_date = row.find('cp-td', {'data-label': 'PublishDate'})

        cve_data = {
            'CVE': cve.get_text(strip=True) if cve else 'N/A',
            'Description': description.get_text(strip=True) if description else 'N/A',
            'Severity': severity.get_text(strip=True) if severity else 'N/A',
            'Publish Date': publish_date.get_text(strip=True) if publish_date else 'N/A'
        }

        cve_list.append(cve_data)
else:
    print("No rows found in the table.")


driver.quit()

for cve_data in cve_list:
    print(cve_data)
