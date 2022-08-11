# importing the MISPSampleRunner class to run the project as necessary. Refer to MISPSampleRunner.py to see more details. 
from MISPSampleRunner import MISPSampleRunner as Runner 

def main():
    """
    This script runs the entire Sample Project for the Threat Intelligence API. 
    To run: enter the correct directory and enter the command 'python3 script.py'
    To read: look at MISPSampleRunner.py to see what classes are called when. 
    """
    Runner.run()

if __name__ == '__main__':
    main()
