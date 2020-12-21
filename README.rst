.. image:: https://raw.githubusercontent.com/CityOfZion/visual-identity/develop/_CoZ%20Branding/_Logo/_Logo%20icon/_PNG%20200x178px/CoZ_Icon_DARKBLUE_200x178px.png
    :alt: CoZ logo


NEO3VM
------
C++ implementations of cryptographic functions used in the NEO3 Blockchain with bindings for Python 3.7 & 3.8.

The current version only supports EllipticCurve functions by wrapping `micro-ecc <https://github.com/kmackay/micro-ecc>`_)
and exposing helper classes. ``SECP256R1`` (a.k.a ``NIST256P``) and ``SECP256K1`` are the only curves exposed, but others can easily
be enabled if needed.

Installation
~~~~~~~~~~~~
::

    pip install neo3crypto

Or download the wheels from the Github releases page.

Usage
~~~~~

::

    import hashlib
    from neo3crypto import ECCCurve, KeyPair, ECDSA

    kp = KeyPair.generate(ECCCurve.SECP256R1)
    ecdsa = ECDSA(ECCCurve.SECP256R1, hashlib.sha256)

    signature = ecdsa.sign(kp.private_key, b'message')
    assert ecdsa.verify(signature, b'message', kp.public_key) == True

Any hashlib hashing function can be used. Further documentation on the classes can be queried from the extension module
using ``help(neo3crypto)``.

Building wheels
~~~~~~~~~~~~~~~
Make sure to have ``wheel`` and ``CMake`` installed. Then call ``python setup.py bdist_wheel``.