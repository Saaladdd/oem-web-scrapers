from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
import time
from datetime import date,datetime
from bs4 import BeautifulSoup

today = date.today()

options = Options()
#options.add_argument("--headless")
options.add_argument("--disable-notifications")

driver = webdriver.Chrome(options=options)

url = "https://www.intel.com/content/www/us/en/security-center/default.html"

cve_list = []
try:
    driver.get(url) 
    
    table = WebDriverWait(driver, 20).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, ".table.image-rendition-feature.sorting"))
    )
    time.sleep(1)
    table_rows = table.find_elements(By.TAG_NAME, "tr")
    rows = table_rows[:5]
    for row in rows :
        columns = row.find_elements(By.TAG_NAME, "td")
        if len(columns) > 0:
            cve_link = columns[0].find_element(By.TAG_NAME, "a").get_attribute("href")
            cve_title = columns[0].get_attribute("textContent")
            latest_version_date = datetime.strptime(columns[2].get_attribute("textContent"), "%B %d, %Y").date()
            print(cve_link, cve_title, latest_version_date)
            cve_list.append({"CVE Link": cve_link, "Title": cve_title, "Date": latest_version_date})
            time.sleep(2)

    for index,links in enumerate(cve_list):
        link = links['CVE Link']
        driver.get(link)
        try:
            table = WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, ".table.image-rendition-feature"))
            )
            time.sleep(1)
            table_rows = table.find_elements(By.TAG_NAME, "tr")
            for i in range(0,5):
                columns = table_rows[i].find_elements(By.TAG_NAME, "td")
                print(columns)
                if i == 0:
                    cve_link = columns[1].text
        except Exception as e:
            print(f"An error occurred: {e}")


except Exception as e:
    print(f"An error occurred: {e}")

finally:
    driver.quit()
