from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
import json
import time

#initialize the web and blocks the pop-ups.
options = Options()
options.add_argument("--disable-notifications")
options.add_argument("--start-maximized")

driver = webdriver.Chrome(options=options)

#stores the target URL.
url = "https://holdings.panasonic/global/corporate/product-security/psirt/advisories.html"

#tracks advisories processed to prevent duplicates.
seen_advisories = set()

#place the code in try-catch block.
try:
    print("Starting real-time advisory tracking...")
    while True:
        #infinite loop to continously scrape the site.
        driver.get(url)
        time.sleep(3) #loads the page.

        #extracts all the data.
        advisories = driver.find_elements(By.CSS_SELECTOR, "div.cmp-container > div.aem-Grid > div.richtext")

        current_advisories = []
        for i in range(0, len(advisories), 3):
            try:
                # extracts date using selector.
                date = advisories[i].find_element(By.CSS_SELECTOR, "span.caption_3_cf").text.strip()

                # provides title through extraction.
                title = advisories[i + 1].find_element(By.CSS_SELECTOR, "span.caption_1_cf").text.strip()

                # CVE ID and reporters.
                cve_info = advisories[i + 2].find_element(By.CSS_SELECTOR, "span.caption_1_cf").text.strip()

                # provides links.
                link = advisories[i + 2].find_element(By.CSS_SELECTOR, "a").get_attribute("href")

                advisory_tuple = (date, title, cve_info, link)

                if advisory_tuple not in seen_advisories:
                    seen_advisories.add(advisory_tuple)
                    current_advisories.append({
                        "Date": date,
                        "Title": title,
                        "CVE Info": cve_info,
                        "Link": link
                    })
            except Exception as e:
                print(f"Error processing advisory: {e}")

        # Print new advisories in real time
        if current_advisories:
            print("\nNew Advisories Detected:")
            print(json.dumps(current_advisories, indent=4, ensure_ascii=False))

            # Append new advisories to a JSON file
            with open("real_time_cve_data.json", "a", encoding="utf-8") as file:
                for advisory in current_advisories:
                    file.write(json.dumps(advisory, ensure_ascii=False) + "\n")
        else:
            print("\nNo new advisories detected.")
        time.sleep(20)

except KeyboardInterrupt:
    print("\nReal-time tracking stopped.")

except Exception as e:
    print(f"An error occurred: {e}")

#closes the browser
finally:
    driver.quit()
