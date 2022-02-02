#!/bin/bash
echo "Running Make Env Script"

# make virtual environment
python3 -m venv env
echo "Succesfully made virtual environment called env"

# activate virtual environment
source env/bin/activate
echo "Virtual environment activated"

# update pip
pip install --upgrade pip
echo "Upgraded pip"

# install requirements
pip install -r requirements.txt
echo "Successfully installed required packages"

# done
echo "Make Env Script - Finished"
