import json
import logging
import os
from threading import Thread

import requests
from solvers.svgcaptcha import solver
from websockets.sync.client import connect

logging.basicConfig(level=logging.ERROR,
                    format='\n%(asctime)s %(levelname)s %(message)s', datefmt='%H:%M:%S')


class MyEDU:
    def __init__(self):
        self.username, self.password = self.get_and_set_authentication()
        self.token = self.get_token()

    def get_and_set_authentication(self):
        mode = "w+"
        if os.path.exists('authentication.txt'):
            mode = "r"

        with open('authentication.txt', mode) as f:
            username = ""
            password = ""

            text = f.read()

            if text:
                text = json.loads(text.strip())
                username = text.get("username")
                password = text.get("password")

            if not username or not password:
                username = input("\nEnter your my.edu username:\n")
                password = input("\nEnter your my.edu password:\n")
                f.write(json.dumps(
                    {"username": username, "password": password}))

            return username, password

    def get_captcha(self):
        captcha_url = "https://my.edu.sharif.edu/api/auth/captcha"
        captcha_response = requests.request("GET", captcha_url)

        try:
            captcha_response = captcha_response.json()
            captcha = captcha_response["data"]
            challenge = captcha_response["challenge"]
            return captcha, challenge

        except Exception as e:
            logging.error(f"Exception: get_captcha() -> {repr(e)}")
            exit()

    def solve_captcha(self):
        try:
            captcha, challenge = self.get_captcha()
            solved_captcha = solver.solve_captcha(captcha)
            return solved_captcha, challenge

        except Exception as e:
            logging.error(f"Exception: solve_captcha() -> {repr(e)}")
            exit()

    def get_token(self):
        solved_captcha, challenge = self.solve_captcha()
        payload = json.dumps({"username": self.username,
                              "password": self.password, "challenge": challenge, "captcha": solved_captcha})
        headers = {"content-type": "application/json"}
        url = "https://my.edu.sharif.edu/api/auth/login"

        try:
            response = requests.request(
                "POST", url, headers=headers, data=payload)
            response = response.json()
            return response["token"]

        except Exception as e:
            logging.error(f"Exception: get_token() -> {repr(e)}")
            exit()

    def cource_actions(self, action, course):
        results = []
        payload = json.dumps({"action": action, "course": course})
        headers = {"content-type": "application/json",
                   "authorization": self.token}
        url = "https://my.edu.sharif.edu/api/reg"

        try:
            response = requests.request(
                "POST", url, headers=headers, data=payload)
            response = response.json()

            for job in response["jobs"]:
                if job['courseId'] == course:
                    results.append({job['courseId']: job['result']})
                    break
        except Exception as e:
            logging.error(f"Exception: reg_cource() -> {repr(e)}")
            results.append({course: "Failed"})

        print("\n".join(
            [f"{list(result.keys())[0]}: {list(result.values())[0]}" for result in results]))

    def get_favorites(self):
        try:
            with connect(f"wss://my.edu.sharif.edu/api/ws?token={self.token}") as websocket:
                websocket.send(f"token={self.token}")
                messages = websocket.recv()
                messages = json.loads(messages)

                if messages['type'] == "userState":
                    return messages['message']['favorites']

        except Exception as e:
            logging.error(f"Exception: get_favorites() -> {repr(e)}")
            return []


my_edu = MyEDU()

list_of_actions = ["1. Register for your favorite courses",
                   "2. Register one course", "3. Remove the course", "4. Change group of the course"]
action = input(
    "\nPlease Select one of the actions below:\n" + "\n".join(list_of_actions) + "\n")

while action not in [str(number) for number in range(1, len(list_of_actions) + 1)]:
    print("\nInvalid input!\n")
    action = input(
        "\nPlease Select one of the actions below:\n" + "\n".join(list_of_actions) + "\n")

if action == "1":
    confirm = input(
        "\nAre you sure you want to register for your favorite courses? (y/n)\n")

    while confirm.lower() not in ["y", "n"]:
        print("\nInvalid input!\n")
        confirm = input(
            "\nAre you sure you want to register for your favorite courses? (y/n)\n")

    if confirm.lower() == "y":
        favorites = my_edu.get_favorites()

        for course in favorites:
            Thread(target=my_edu.cource_actions,
                   args=("add", course)).start()

    elif confirm.lower() == "n":
        print("\nOK, Bye!\n")

elif action == "2":
    course = input("\nRegistering the course...\nEnter the course id:\n")
    my_edu.cource_actions("add", course)

elif action == "3":
    course = input("\nRemoving the course...\nEnter the course id:\n")
    my_edu.cource_actions("remove", course)

elif action == "4":
    course = input("\nRemoving the course...\nEnter the course id:\n")
    my_edu.cource_actions("change", course)