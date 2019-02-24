#!/usr/bin/env python
from __future__ import print_function

import setuptools
import codecs

long_description = ''
with codecs.open('./README.rst', encoding='utf-8') as readme:
    long_description = readme.read()

setuptools.setup(
     name='virustotal-api-v2',  
     version='0.8',
     packages=['vt',] ,
     author="Tal Melamed",
     author_email="dev@appsec.it",
     description="Python scripts to interact with the virustotal.com API",
     long_description=long_description,
     url="https://github.com/nu11p0inter/virustotal",
     classifiers=[
         "Programming Language :: Python :: 2.7",
         "License :: OSI Approved :: MIT License",
         "Operating System :: OS Independent",
     ],
	 zip_safe=False,
     include_package_data=True,
     install_requires=["requests >= 2.2.1"]
 )

