### CloudFinderWeb

Been trying to find a full solution that works for checking if a IP address is part of a Cloud Service Provider.

This stands up a simple web page to submit a IP address and optionally update all the lists below.

#### Services so far:
* AWS
* GCP
* Cloudflare
* Fastly
* OCI
* Linode
* GitHub
* DigitalOcean
* Akamai
* Microsoft Azure
* Microsoft O365
* IBM Cloud
* Zscaler

#### Start Flask
>python .\cloud_finder.py

#### Start Gunicorn (Only works on Unix or WSL2)
>gunicorn -b 127.0.0.1:5050 -w 4 "cloud_finder:app"
 
Note: You will need to install gunicorn with
>pip install gunicorn

<a href="http://localhost:5050">Go Locally Hosted Page!</a>

#### Example
Submit IP address to check:

![Web Page For Submission](2023-10-26_19-50-12.png)

Response

![Response](2023-10-26_19-50-29.png)

<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">Creative Commons Attribution-ShareAlike 4.0 International License</a>.
