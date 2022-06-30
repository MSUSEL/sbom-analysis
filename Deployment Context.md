# Deployment Context
Should be provided by the party who will be using/deploying the software. For use in analyzing software based on where it will be deployed and the components & vulnerabilies that compose the software.

| Score | Capacity |
|-|-|
| Network | Internet/network interaction |
| Permissions | Commandline/Filesystem interaction |
| Information Sensitivity | How compromising the information the software has access to |

#### Network
* ##### Public Access
    The software is fully accessible with the public network
* ##### Internal Access
    The software is accessible by way of other services
* ##### Restricted
    The software runs is deployed in an environment with network access but is not allowed to use the network.
* ##### Isolated
    The software is not deployed with internet access

#### Permissions
* ##### Full
    The software can access and modify anything it wants.
* ##### Non-Protected
    The software cannot access non-owned or admin programs/services 
* ##### Restricted
    The software is only allowed to access/modify function essential services
* ##### None
    The software is cut off from accessing the filesystem/commandline because functionalities that use them are not needed

#### Information Sensitivity
* ##### Compromising
    The information is usable and can be used compromise or identify specific individuals contained in the dataset 
* ##### Medium
    The information may be marketable or usable but does not compromise identifiable individuals (on its own)
* ##### Low
    The information the service has access to is not useful to an attacker