import requests
from bs4 import BeautifulSoup
import time

url = "https://www.oracle.com/security-alerts/#CriticalPatchUpdates"
shortened_url = "https://www.oracle.com"
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
}

try:
    response = requests.get(url, headers=headers)

except Exception as e:
    print(f"An error occurred: {e}")


def get_date(date_str: str) -> str:
    formatted_date = date_str.split(",")[1].strip()
    return formatted_date

def get_product_name(full_string: str) -> list:
    if "versions" in full_string:
        product_name = full_string.split("versions")[0]
    elif "version" in full_string:
        product_name = full_string.split("version")[0]
    else:
        return []
    all_products = [product.strip() for product in product_name.split(",") if product.strip()]
    return all_products

def get_product_version(full_string: str) ->list:
    if "versions" in full_string:
        product_version = full_string.split("versions")[1]
    elif "version" in full_string:
        product_version = full_string.split("version")[1]
    else:
        return []

    all_versions = [version.strip() for version in product_version.split(",")]
    return all_versions


try:
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        outer_div = soup.find_all('div', class_='otable otable-sticky otable-tech')
        outer_div = outer_div[1]
        cve_list = []
        if outer_div:
            inner_div = outer_div.find('div', class_='otable-w1')

            if inner_div:
                table = inner_div.find('table', class_='otable-tech-basic otable-w2')

                if table:
                    rows = table.find_all('tr')

                    for row in rows:
                        columns = row.find_all('td')
                        if columns:
                            column_text = [col.text.strip() for col in columns]
                            link_tag = columns[0].find('a', href=True)
                            if link_tag:
                                link = link_tag['href']
                            else:   
                                None
                            date = get_date(column_text[1])
                            title = column_text[0]
                            cve_list.append({"CVE Link": link, "Title": title, "Date": date})

    else:
        print(f"Failed to retrieve the page. Status code: {response.status_code}")

    for i in range(0,len(cve_list)):
        link = cve_list[i]["CVE Link"]
        link = shortened_url + link
        response = requests.get(link, headers=headers)
        if response.status_code == 200:
            time.sleep(2)
            soup = BeautifulSoup(response.text, 'html.parser')
            outer_section = soup.find_all('section', class_='cc02 cc02v4 cpad')
            target_div = outer_section[0].find('div', class_='cc02w1 cwidth')
            h3_tags = target_div.find_all('h3')
            if len(h3_tags) >= 2:
                first_h3 = h3_tags[0]
                second_h3 = h3_tags[1]
                paragraphs = []
                current_tag = first_h3.find_next_sibling()
                
                while current_tag and current_tag != second_h3:
                    if current_tag.name == 'p':
                        paragraphs.append(current_tag.text.strip())
                    current_tag = current_tag.find_next_sibling()
                description = " ".join(paragraphs)
                cve_list[i].update({"Description": description})
            
            main_table_div = target_div.find('div', class_='otable otable-sticky otable-tech')
            table_div = main_table_div.find('div', class_='otable-w1')
            if table_div:
                table = table_div.find('table', class_='otable-tech-basic otable-w2')
                if table:
                    rows = table.find_all('tr')
                    for row in rows:
                        columns = row.find_all('td')
                        if columns:
                            column_text = [col.text.strip() for col in columns]
                            product = column_text[0]
                            product_names = get_product_name(product)
                            product_versions = get_product_version(product)
                            remedy_tag = columns[1].find('a', href=True)
                            if remedy_tag:
                                remedy = remedy_tag['href']
                            cve_list[i].update({"Affected Products": product_names, 
                                                "Affected Versions": product_versions,
                                                "Remedy": remedy, "Severity": "High"})

except Exception as e:
    print(f"An error occurred: {e}")


print(cve_list)



