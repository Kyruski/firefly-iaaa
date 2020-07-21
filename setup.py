#  Copyright (c) 2019 JD Williams
#
#  This file is part of Firefly, a Python SOA framework built by JD Williams. Firefly is free software; you can
#  redistribute it and/or modify it under the terms of the GNU General Public License as published by the
#  Free Software Foundation; either version 3 of the License, or (at your option) any later version.
#
#  Firefly is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
#  Public License for more details. You should have received a copy of the GNU Lesser General Public
#  License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#  You should have received a copy of the GNU General Public License along with Firefly. If not, see
#  <http://www.gnu.org/licenses/>.

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='firefly-iaaa',
    version='0.1.4',
    author="JD Williams",
    author_email="me@jdwilliams.xyz",
    description="Bounded context for users of your application.",
    long_description=long_description,
    url="https://github.com/firefly-framework/firefly-iaaa",
    packages=setuptools.PEP420PackageFinder.find('src'),
    package_dir={'': 'src'},
    install_requires=[
        'bcrypt>=3.1.7',
        'firefly-framework>=1.0.24',
    ],
    extras_require={
        'AWS Cognito Support': ['firefly-aws>=1.0.20'],
    },
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Operating System :: OS Independent",
    ],
)
