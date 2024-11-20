from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
import time
from datetime import date,datetime
import re

today = date.today()

options = Options()
options.add_argument("--headless")
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
            latest_version_date = columns[2].get_attribute("textContent")
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
            table_body = table.find_elements(By.TAG_NAME, "tbody")
            table_rows = table_body[0].find_elements(By.TAG_NAME, "tr")
            page_source = driver.page_source
            description = driver.find_element(By.XPATH, "//h3[contains(text(), 'Summary:')]/following-sibling::p").text
            description = description.replace("\n","")
            remedy = driver.find_element(By.XPATH, "//h3[text()='Recommendation:']/following-sibling::p").text
            remedy = remedy.replace("\n","")
            affected_device = driver.find_element(By.XPATH, "//h3[text()='Affected Products:']/following-sibling::p").text
            cve_ids = re.findall(r'CVE-\d{4}-\d+', page_source)
            cve_scores = re.findall(r'CVSS Base Score 4.0: \d+\.\d+ \w+', page_source)
            cve_list[index].update({"Remedy": remedy, "Affected Device": affected_device,"Description": description, "CVE ID": cve_ids, "CVSS Score": cve_scores})
            

            for i in range(0,5):
                columns = table_rows[i].find_elements(By.TAG_NAME, "td")
                if i == 0:
                    category = columns[1].text
                    cve_list[index].update({"Category": category})
                elif i == 1:
                    impact = columns[1].text
                    cve_list[index].update({"Impact": impact})
                elif i == 2:
                    severity = columns[1].text
                    cve_list[index].update({"Severity": severity})
                
               
        except Exception as e:
            print(f"An error occurred: {e}")


except Exception as e:
    print(f"An error occurred: {e}")

finally:
    print(cve_list[0])
    driver.quit()
