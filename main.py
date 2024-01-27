import asyncio
import json
import logging
import os
import sys
import time
from threading import Thread

import requests
import websockets
from solvers.svgcaptcha import solver

logging.basicConfig(level=logging.ERROR,
                    format='\n%(asctime)s %(levelname)s %(message)s', datefmt='%H:%M:%S')


def worker(func, loop):
    asyncio.set_event_loop(loop)
    loop.run_until_complete(func())


class MyEDU:
    def __init__(self):
        self.username, self.password = self.get_and_set_authentication()
        self.token = self.get_token()
        self.all_courses = []
        self.favorites = []

    def request_and_retry(self, method, url, json_data, headers, desired_status_code, waiting_times=[0, 3, 7]):
        try:
            max_retries = len(waiting_times)
            retries = 0
            while retries < max_retries:
                i = retries
                retries += 1
                if waiting_times[i] > 0:
                    time.sleep(waiting_times[i])

                if type(json_data) == dict:
                    response = requests.request(
                        method, url=url, json=json_data, headers=headers)
                else:
                    response = requests.request(
                        method, url=url, data=json_data, headers=headers)

                if response.status_code == desired_status_code:
                    result = response.json()

                    if result == {'error': 'AUTHORIZATION'}:
                        self.token = self.get_token()
                        continue

                    return result

            logging.error(
                f"Exception: request_and_retry() -> response status code: {response.status_code}, response: {response.json()}")
            sys.exit()

        except Exception as e:
            logging.error(f"Exception: request_and_retry() -> {repr(e)}")
            sys.exit()

    def get_and_set_authentication(self):
        username = ""
        password = ""

        if os.path.exists('authentication.txt'):
            with open('authentication.txt', "r") as f:
                text = f.read()

                if text:
                    text = json.loads(text.strip())
                    username = text.get("username")
                    password = text.get("password")

        if not username or not password:
            with open('authentication.txt', "w+") as f:
                username = input("\nEnter your my.edu username:\n")
                password = input("\nEnter your my.edu password:\n")
                f.write(json.dumps(
                    {"username": username, "password": password}))

        return username, password

    def get_token(self):
        solved_captcha, challenge = self.solve_captcha()
        payload = json.dumps({"username": self.username,
                              "password": self.password, "challenge": challenge, "captcha": solved_captcha})
        headers = {"content-type": "application/json"}
        url = "https://my.edu.sharif.edu/api/auth/login"

        try:
            response = self.request_and_retry(
                method="POST", url=url, json_data=payload, headers=headers, desired_status_code=200)
            return response["token"]

        except Exception as e:
            logging.error(
                f"Exception: get_token() -> {repr(e)} - response: {response}")
            sys.exit()

    def get_captcha(self):
        captcha_url = "https://my.edu.sharif.edu/api/auth/captcha"
        captcha_response = self.request_and_retry(
            method="GET", url=captcha_url, json_data=None, headers=None, desired_status_code=200)
        try:
            captcha = captcha_response["data"]
            challenge = captcha_response["challenge"]
            return captcha, challenge

        except Exception as e:
            logging.error(f"Exception: get_captcha() -> {repr(e)}")
            sys.exit()

    def solve_captcha(self):
        try:
            captcha, challenge = self.get_captcha()
            solved_captcha = solver.solve_captcha(captcha)
            return solved_captcha, challenge

        except Exception as e:
            logging.error(f"Exception: solve_captcha() -> {repr(e)}")
            sys.exit()

    def cource_actions(self, action, course):
        results = []
        payload = json.dumps(
            {"action": action, "course": course, "units": self.get_course_units(course)})
        headers = {"content-type": "application/json",
                   "authorization": self.token}
        url = "https://my.edu.sharif.edu/api/reg"

        try:
            response = self.request_and_retry(
                method="POST", url=url, json_data=payload, headers=headers, desired_status_code=200)

            for job in response["jobs"]:
                if job['courseId'] == course:
                    results.append({job['courseId']: job['result']})
                    break
        except Exception as e:
            logging.error(f"Exception: reg_cource() -> {repr(e)}")
            results.append({course: "Failed"})

        print("\n".join(
            [f"{list(result.keys())[0]}: {list(result.values())[0]}" for result in results]))

    def get_course_units(self, course_id):
        try:
            for course in self.all_courses:
                if course['id'] == course_id:
                    return course['units']

            raise Exception(f"Units of course {course_id} not found!")

        except Exception as e:
            logging.error(f"Exception: get_course_units() -> {repr(e)}")
            sys.exit()

    def register_all_favorites(self):
        try:
            for course in self.favorites:
                Thread(target=self.cource_actions,
                       args=("add", course)).start()
        except Exception as e:
            logging.error(f"Exception: register_all_favorites() -> {repr(e)}")

    def add_or_update_course(self, courses):
        all_courses_ids = [item['id'] for item in self.all_courses]
        for course in courses:
            if course['id'] in all_courses_ids:
                self.all_courses[all_courses_ids.index(course['id'])] = course
            else:
                self.all_courses.append(course)

    async def get_courses_information(self):
        try:
            async with websockets.connect(f"wss://my.edu.sharif.edu/api/ws?token={self.token}") as websocket:
                while True:
                    await websocket.send(f"token={self.token}")
                    messages = await websocket.recv()
                    messages = json.loads(messages)

                    if messages['type'] == "userState":
                        self.favorites = messages['message']['favorites']
                    elif messages['type'] == "listUpdate":
                        self.add_or_update_course(messages['message'])
        except Exception as e:
            logging.error(f"Exception: get_courses_information() -> {repr(e)}")


my_edu = MyEDU()

loop = asyncio.new_event_loop()
updater = Thread(target=worker, args=(my_edu.get_courses_information, loop,))
updater.start()

list_of_actions = ["1. Register for your favorite courses",
                   "2. Register one course", "3. Remove the course", "4. Change the course group"]

while True:
    action = input(
        "\nPlease Select one of the actions below:\n" + "\n".join(list_of_actions) + "\n")

    if action == "1":
        my_edu.register_all_favorites()

    elif action == "2":
        add_course = input(
            "\n** Registering the course **\nEnter the course id:\nEnter like this:\nCourseID-GroupNumber\nFor example: 40419-1\n")
        my_edu.cource_actions("add", add_course)

    elif action == "3":
        remove_course = input(
            "\n** Removing the course **\nEnter the course id:\nEnter like this:\nCourseID-GroupNumber\nFor example: 40419-1\n")
        my_edu.cource_actions("remove", remove_course)

    elif action == "4":
        new_course = input(
            "\n** Changing the course group **\nEnter the new course id:\nEnter like this:\nCourseID-GroupNumber\nFor example: 40419-1\n")
        my_edu.cource_actions("move", new_course)
    else:
        print("\nInvalid input!\n")
