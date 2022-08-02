# Producing & Understanding the Results of Scayl
## _Radar Chart_
* ### Producing
The file(s) used should be a CSV file with the headers: "id", "sum", "network", "files", "remote", "information", & "permissions". 
The default options for number of files is a single file or three to compare.
From here you can select the CSV file(s) within the radar.R file. Read through all the code and follow the instructions commented to produce a radar bar chart.
The lines that should be run differ depending on if you choose to compare three or not.

* ### Understanding
Each file whether you make one or more will create a net-like shape on the pentagon base. There are 5 axis for the 5 categories. The net is created by plotting the mean score of each category on the corresponding axis. By plotting these 5 points, a net is created. The larger the net, the worse the file scores. It is on a scale from 0 to 1, where 0 is better than 1. Each label also contains the category score for you to analyze. Additionally, an overall score is computed to display. This chart makes it easier to compare files per category in addition to an overall score.

## _Stacked Bar Chart_
* ### Producing
The file used should be a CSV file with the headers: "id", "sum", "network", "files", "remote", "information", & "permissions". From here you can select the CSV within the stackedBar.R file. Read through all the code and follow the instructions commented to produce a default stacked bar chart.
Customizing
The dividing sections can be changed in Section 2.
The title can be changed in Section 3.
The color scheme can be changed inside of Section 3.

* ### Understanding
For full view of the stacked bar chart, ensure that the image is expanded into full view.
The stacked bar chart produced should result in a title containing the total amount of CVEs.
The color code is graphed by severity. A darker color suggests a more severe effect. 
Each column graphs the total number of CVEs. The different categories show how the CVEs affect that category in particular. For example, one CVE might effect "Network Configuration" severly, but not "Command Line Permissions."  So, "Network Configuration" will have an added count of the "High" category that would be shown in dark purple. "Command Line Permissions" would mark that CVE as low and count it for then pale purple category. In this way, you can see where the severity of CVE's line for a program.