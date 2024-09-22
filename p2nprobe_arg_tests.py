""" 
    Jenoduche testy pro zpracovani argumentu prikazove radky.
    Predpoklada se, ze pri kazdem spusteni programu musi byt zadan Host, port a PCAP soubor, jinak
    se jedna o nespravnou kombinaci vstupnich parametru.
"""

__author__          =   "Roman Machala"
__date__            =   "22.09.2024"

import unittest
import subprocess


class TestCProgram(unittest.TestCase):

    def run_c_program(self, *args):
        result = subprocess.run(
                            ["./p2nprobe", *args],
                            capture_output=True, text=True    
                            )
        
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    
    """ -a prepinac je zadan spravne ale nejsou zadany pozadovane argumenty """
    def test_active_invalid(self):
        returncode, output_out, output_err = self.run_c_program('-a', '10')
        self.assertEqual(returncode, 1)
        self.assertEqual(output_out, "")
        self.assertNotEqual(output_err, "")

    def test_active_invalid_2(self):
        returncode, output_out, output_err = self.run_c_program('--active', '10')
        self.assertEqual(returncode, 1)
        self.assertEqual(output_out, "")
        self.assertNotEqual(output_err, "")

    """ -i prepinac je pouzit spravne ale nejsou zadany pozadovane argumenty """
    def test_inactive_invalid(self):
        returncode, output_out, output_err = self.run_c_program('-i', '10')
        self.assertEqual(returncode, 1)
        self.assertEqual(output_out, "")
        self.assertNotEqual(output_err, "")

    def test_inactive_invalid_2(self):
        returncode, output_out, output_err = self.run_c_program('--inactive', '10')
        self.assertEqual(returncode, 1)
        self.assertEqual(output_out, "")
        self.assertNotEqual(output_err, "")

    """ U prepinace -i chybi pozadovana hodnota (+ nejsou vlozeny pozadovane parametry) """
    def test_comb_invalid(self):
        returncode, output_out, output_err = self.run_c_program('-a', '10', '-i')
        self.assertEqual(returncode, 1)
        self.assertEqual(output_out, "")
        self.assertNotEqual(output_err, "")

    """ Zadany vsechny pozadovane argumenty, test musi projit """
    def test_valid(self):
        returncode, output_out, output_err = self.run_c_program('localhost:1010', './temp_file')
        self.assertEqual(returncode, 0)
        self.assertEqual(output_out, "")
        self.assertEqual(output_err, "")

    """ Nasledujici testy jsou validni, zkouseji kombinace parametru """
    def test_valid_2(self):
        returncode, output_out, output_err = self.run_c_program('localhost:1010', './temp_file', '-a', '10')
        self.assertEqual(returncode, 0)
        self.assertEqual(output_out, "")
        self.assertEqual(output_err, "")

    def test_valid_2(self):
        returncode, output_out, output_err = self.run_c_program('localhost:1010', './temp_file', '-i', '10')
        self.assertEqual(returncode, 0)
        self.assertEqual(output_out, "")
        self.assertEqual(output_err, "")

    def test_valid_3(self):
        returncode, output_out, output_err = self.run_c_program('localhost:1010', './temp_file', '-i', '10', '-a', '10')
        self.assertEqual(returncode, 0)
        self.assertEqual(output_out, "")
        self.assertEqual(output_err, "")

    def test_valid_4(self):
        returncode, output_out, output_err = self.run_c_program('localhost:1010', './temp_file', '-a', '10', '-i', '10')
        self.assertEqual(returncode, 0)
        self.assertEqual(output_out, "")
        self.assertEqual(output_err, "")

    def test_valid_5(self):
        returncode, output_out, output_err = self.run_c_program('-a', '10', '-i', '10', 'localhost:1010', './temp_file')
        self.assertEqual(returncode, 0)
        self.assertEqual(output_out, "")
        self.assertEqual(output_err, "")

    def test_valid_6(self):
        returncode, output_out, output_err = self.run_c_program('-a', '10', '-i', '10','./temp_file', 'localhost:1010')
        self.assertEqual(returncode, 0)
        self.assertEqual(output_out, "")
        self.assertEqual(output_err, "")

    def test_valid_7(self):
        returncode, output_out, output_err = self.run_c_program('-a', '10', '-i', '10','./temp_file', '192.168.0.0:1010')
        self.assertEqual(returncode, 0)
        self.assertEqual(output_out, "")
        self.assertEqual(output_err, "")

    """ Nasledujici testy zkouseji kombinace spravne zadanych parametru, ale ve spatnem poradi nebo s chybejicimi hodnotami """
    def test_invalid(self):
        returncode, output_out, output_err = self.run_c_program('-a', '-i', '10','./temp_file', 'localhost:1010')
        self.assertEqual(returncode, 1)
        self.assertEqual(output_out, "")
        self.assertNotEqual(output_err, "")

    def test_invalid_2(self):
        returncode, output_out, output_err = self.run_c_program('-a', '10', '-i', 'invalid_value','./temp_file', 'localhost:1010')
        self.assertEqual(returncode, 1)
        self.assertEqual(output_out, "")
        self.assertNotEqual(output_err, "")

    def test_invalid_3(self):
        returncode, output_out, output_err = self.run_c_program('-a', '10', '-i', '10','./temp_file', 'localhost:')
        self.assertEqual(returncode, 1)
        self.assertEqual(output_out, "")
        self.assertNotEqual(output_err, "")

    def test_invalid_4(self):
        returncode, output_out, output_err = self.run_c_program('-a', '10', '-i', '10','./temp_file', 'localhost:port')
        self.assertEqual(returncode, 1)
        self.assertEqual(output_out, "")
        self.assertNotEqual(output_err, "")

    def test_invalid_5(self):
        returncode, output_out, output_err = self.run_c_program('-a', '10', '-i', '10','./temp_file', ':port')
        self.assertEqual(returncode, 1)
        self.assertEqual(output_out, "")
        self.assertNotEqual(output_err, "")

    def test_invalid_6(self):
        returncode, output_out, output_err = self.run_c_program('-a', '10', '-i', '10','./temp_file', ':1010')
        self.assertEqual(returncode, 1)
        self.assertEqual(output_out, "")
        self.assertNotEqual(output_err, "")

    def test_invalid_7(self):
        returncode, output_out, output_err = self.run_c_program('-a', '10', '-i', '10','./temp_file', ':')
        self.assertEqual(returncode, 1)
        self.assertEqual(output_out, "")
        self.assertNotEqual(output_err, "")





if __name__ == '__main__':
    unittest.main()