# MSU REU 2022
# Gianforte School of Computing, Montana State University
# Created By: Cynthia Rosas
# Creating a Radar Chart for Scayl Results
################################################################
###---Library Used for the Radar Chart---###
library(fmsb) 
################################################################
###---Choose your file---###
df<-read.csv(file=file.choose())
################################################################
###---Creates the new data frame of means---###
data <- data.frame (network = c(mean(df$network)),
                    remote = c(mean(df$remote)),
                    sensitivity = c(mean(df$information)),
                    clperms = c(mean(df$permissions)),
                    fperms = c(mean(df$files)))
################################################################
###---Adds the Ceiling and Floor of the Mean Dataframe---###
data <- rbind(rep(1.0,5) , rep(0.0,5) , data)
################################################################
###---Changes the Column Names to Include the Score---###
colnames(data) <- c(paste("Network\nConfiguration\n ",signif(data$network[3],3)),
                    paste("Remote\nAccess\n",signif(data$remote[3],3)),
                    paste("Information\nSensitivity\n",signif(data$sensitivity[3],3)),
                    paste("Command Line\nPermissions\n",signif(data$clperms[3],3)) ,
                    paste("File\nPermissions\n",signif(data$fperms[3],3)))
################################################################
###---Title & Background for the Radar Chart---###
theTitle<-paste("SCAYL RESULTS\n Overall: ",signif(mean(df$sum)/5,3))
par(bg = " light grey")
################################################################
###---Radar Chart--###
radarchart(axistype=1, # The axis are included
           seg= 5, # The number of segments
           pcol = rgb(0.6,0.5,0.9,0.9), # The colors of the connected lines
           plwd= 4, # The thickness of the  connected lines
           pfcol=rgb(0.6,0.5,0.9,0.3), # The fill color of the connected lines
           cglty=1, # The chart line type
           cglwd=0.8, # The chart line thickness 
           cglcol=rgb(0.5,0.5,0.5), # The chart line color
           axislabcol = 'white', # The color of the axis 
           caxislabels=seq(0,1,0.2),# The intervals of the axis
           title= theTitle, #The title -- set earlier
           vlcex=0.8, # The labels
           data)
################################################################
