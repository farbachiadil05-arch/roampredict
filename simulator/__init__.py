"""Simulated school floor for testing RoamPredict without Wi-Fi hardware.

* ``floorplan``  - 2-D building: classrooms, a hallway, walls with dB loss, APs.
* ``radio``      - path loss + wall attenuation + slow shadowing + reading noise
                   + occasional one-sample "hand over the antenna" dips.
* ``walker``     - a virtual person walking scripted routes.
* ``link_model`` - how long switches take (full 802.1X, cached key, 802.11r).
                   ALL NUMBERS ARE ASSUMPTIONS - replace them with measurements.
* ``strategies`` - the simulated Windows driver plus the three strategies.
* ``run``        - runs many random seeds and prints the comparison table.
* ``plot``       - matplotlib figures.
"""
