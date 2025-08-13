import json
import random
import string

import requests


def create_customer_paths(cust_count: int) -> list[str]:
    prefixes = [
        "serviceAccounts/local/",
        "serviceAccounts/admin/",
        "serviceAccounts/monitor/",
        "serviceAccounts/audit/",
        "serviceAccounts/orch/",
    ]
    entries = []
    for prefix in prefixes:
        for num in range(1, cust_count + 1):
            entries.append(f"{prefix}cust{num}")
    return entries


def add_entry_names_to_customers(names: list[str]) -> list[str]:
    entries = []
    max_entries = random.randint(1, 200)  # nosec
    for path in names:
        for num in range(1, max_entries + 1):
            entries.append(f"{path}/machine{num}")
    return entries


def create_data_for_entries(entry_paths: list):
    res = dict()
    for path in entry_paths:
        max_entries = random.randint(1, 9)  # nosec
        pws = []
        for _num in range(0, max_entries):
            passwd = "".join(
                random.choices(string.ascii_letters + string.digits, k=20)
            )  # nosec
            pws.append(passwd)
        res[path] = pws
    return res


def write_data_to_vault(entries: dict):
    url = "http://localhost:8200/v1/secret/data/"
    for path, pw_list in entries.items():
        final_url = f"{url}{path}"
        print(f"creating entries for '{path}'")
        for passwd in pw_list:
            data = dict()
            body = dict()
            data["passwd"] = passwd
            body["data"] = data
            body_json = json.dumps(body)
            token = ""  # nosec
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            resp = requests.post(
                url=final_url, headers=headers, data=body_json, timeout=60
            )
            if not resp.ok:
                print(f"failed to post entry for '{path}'")


if __name__ == "__main__":
    customers = create_customer_paths(100)
    machines = add_entry_names_to_customers(customers)
    seed_data = create_data_for_entries(machines)
    write_data_to_vault(seed_data)
