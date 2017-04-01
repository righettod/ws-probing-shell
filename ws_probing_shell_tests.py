import unittest
import json
from ws_probing_shell import WSProbingShell


class TestWSShell(unittest.TestCase):
    """
    Integration tests for the main commands of the WS Shell
    Parallel run of tests is not supported because file are used to read command result
    According to the number of test is not an issue
    """

    def test_replay(self):
        """
        Test case for the REPLAY command
        """
        # Run command using test material
        instance = WSProbingShell()
        instance.do_connect("-t ws://echo.websocket.org")
        instance.do_replay("-m testing_material/msg_replay.txt -n 2")
        instance.do_disconnect("")
        instance.do_quit("")
        # Validate the test
        with open("exchanges_replay.json", "r") as msg_file:
            data = json.load(msg_file)
            self.assertEqual(len(data), 2)
            self.assertEqual("TEST MESSAGE", data["0"]["REQUEST"])
            self.assertEqual("TEST MESSAGE", data["1"]["REQUEST"])
            self.assertEqual("TEST MESSAGE", data["0"]["RESPONSE"])
            self.assertEqual("TEST MESSAGE", data["1"]["RESPONSE"])
            self.assertFalse(data["0"]["IS_ERROR"])
            self.assertFalse(data["1"]["IS_ERROR"])

    def test_fuzz(self):
        """
        Test case for the FUZZ command
        """
        # Run command using test material
        instance = WSProbingShell()
        instance.do_connect("-t ws://echo.websocket.org")
        instance.do_fuzz("-m testing_material/msg_fuzzing.txt -p testing_material/payload1.txt testing_material/payload2.txt")
        instance.do_disconnect("")
        instance.do_quit("")
        # Validate the test
        with open("exchanges_fuzzing.json", "r") as msg_file:
            data = json.load(msg_file)
            self.assertEqual(len(data), 2)
            self.assertEqual("TEST A FROM C", data["0"]["REQUEST"])
            self.assertEqual("TEST B FROM C", data["1"]["REQUEST"])
            self.assertEqual("TEST A FROM C", data["0"]["RESPONSE"])
            self.assertEqual("TEST B FROM C", data["1"]["RESPONSE"])
            self.assertFalse(data["0"]["IS_ERROR"])
            self.assertFalse(data["1"]["IS_ERROR"])

    def test_search_casesensitive(self):
        """
        Test case for the SEARCH command in case sensitive mode
        """
        # Run command using test material
        instance = WSProbingShell()
        instance.do_connect("-t ws://echo.websocket.org")
        instance.do_fuzz("-m testing_material/msg_fuzzing.txt -p testing_material/payload1.txt testing_material/payload2.txt")
        instance.do_search("-w B")
        instance.do_disconnect("")
        instance.do_quit("")
        # Validate the test
        with open("exchanges_searching.json", "r") as msg_file:
            data = json.load(msg_file)
            self.assertEqual(len(data), 1)
            self.assertEqual("1", data["B"].strip())

    def test_search_caseinsensitive(self):
        """
        Test case for the SEARCH command in case insensitive mode
        """
        # Run command using test material
        instance = WSProbingShell()
        instance.do_connect("-t ws://echo.websocket.org")
        instance.do_fuzz("-m testing_material/msg_fuzzing.txt -p testing_material/payload1.txt testing_material/payload2.txt")
        instance.do_search("-i -w test")
        instance.do_disconnect("")
        instance.do_quit("")
        # Validate the test
        with open("exchanges_searching.json", "r") as msg_file:
            data = json.load(msg_file)
            self.assertEqual(len(data), 1)
            self.assertEqual("0 1", data["test"].strip())

if __name__ == '__main__':
    unittest.main()



