# MSU REU 2022
# Gianforte School of Computing, Montana State University
# Created By: Cynthia Rosas
# Creating a Radar Chart for Scayl Results

################################################################
###---Library Used for the Radar Chart---###

library(fmsb)


################################################################
# SECTION 1: The first choice is to decide if you want to run
# one file or compare. If you are comparing, the default written
# is three files, but you can manually change that. Regardless of
# the number of files you choose, read the comments guiding you
# on what chunks of code to run (or not run) for what you need.
# This sections allows you to choose your files and write in
# their names.
################################################################

# STEP 1: Choose your file(s)
df<-read.csv(file=file.choose())
# If comparing also run this
df2<-read.csv(file=file.choose())
df3<-read.csv(file=file.choose())


################################################################
# STEP 2: Enter the Name of File(s)
df1Name<-"D1"
# If comparing also run this
df2Name<-"D2"
df3Name<-"D3"

################################################################
# SECTION 2: This section involved the data manipulation. The
# first step creates a data frame (or 3) of the mean of each
# category. Then, we add a ceiling and floor to the data. This
# tells the graph what our high and low is for each score. For
# most steps, it does not matter if you run parts of the code for
# a single file when comparing, however, STEP 3 is finicky, try
# to only run the chunk you need. This step is adding in the names
# and scores to the graph. STEP 4 is only needed if comparing
# because it is to list the scores in the legend later.
################################################################

# STEP 1: Creates the new data frame(s) of means
data1 <- data.frame (network = c(mean(df$network)),
                     fperms = c(mean(df$files)),
                    remote = c(mean(df$remote)),
                    sensitivity = c(mean(df$information)),
                    clperms = c(mean(df$permissions)))

# If comparing also run this
data2 <- data.frame (network = c(mean(df2$network)),
                     fperms = c(mean(df2$files)),
                    remote = c(mean(df2$remote)),
                    sensitivity = c(mean(df2$information)),
                    clperms = c(mean(df2$permissions)))
data3 <- data.frame (network = c(mean(df3$network)),
                     fperms = c(mean(df3$files)),
                    remote = c(mean(df3$remote)),
                    sensitivity = c(mean(df3$information)),
                    clperms = c(mean(df3$permissions)))


################################################################
# STEP 2: Adds the Ceiling and Floor of the Mean Data frame(s)
data <- rbind(rep(1.0,5) , rep(0.0,5) , data1)
# If comparing run this instead#
data <- rbind(rep(1.0,5) , rep(0.0,5) , data1,data2,data3)


################################################################
# STEP 3: Changes the Column Names to Include the Score
colnames(data) <- c(paste("Network\nConfiguration\n ",signif(data$network[3],3)),
                    paste("File\nPermissions\n ",signif(data$fperms[3],3)),
                    paste("Remote\nAccess\n ",signif(data$remote[3],3)),
                    paste("Information\nSensitivity\n ",signif(data$sensitivity[3],3)),
                    paste("Command Line\nPermissions\n ",signif(data$clperms[3],3)) )
# If comparing run this instead
colnames(data) <- c(paste("Network\nConfiguration\n ",df1Name,":",signif(data$network[3],3),
                          df2Name,":",signif(data$network[4],3),
                          df3Name,":",signif(data$network[5],3)),
                    paste("File\nPermissions\n ",df1Name,":",signif(data$fperms[3],3),"\n",
                          df2Name,":",signif(data$fperms[4],3),"\n",
                          df3Name,":",signif(data$fperms[5],3)),
                    paste("Remote\nAccess\n ",df1Name,":",signif(data$remote[3],3),"\n",
                          df2Name,":",signif(data$remote[4],3),"\n",
                          df3Name,":",signif(data$remote[5],3)),
                    paste("Information\nSensitivity\n ",df1Name,":",signif(data$sensitivity[3],3),
                          df2Name,":",signif(data$sensitivity[4],3),
                          df3Name,":",signif(data$sensitivity[5],3)),
                    paste("Command Line\nPermissions\n ",df1Name,":",signif(data$clperms[3],3),
                          df2Name,":",signif(data$clperms[4],3),
                          df3Name,":",signif(data$clperms[5],3)))

################################################################
# STEP 4: Change Row Names
# If comparing also run this
rownames(data) <- c("High","Low",
                    paste(df1Name,"\n Overall:",signif(mean(df$sum)/5,3)),
                    paste(df2Name,"\n Overall:",signif(mean(df2$sum)/5,3)),
                    paste(df3Name,"\n Overall:",signif(mean(df3$sum)/5,3)))


################################################################
# SECTION 3: This is the last section and involves making the
# graph. The first step is to find the overall score and title
# for a single file. We also set the background color. If you
# are comparing, then you set the title for that there. The second
# step is the actual graph. If you are comparing, make sure to
# comment of the indicated line for better visibility. Lastly, run
# STEP 3 if you are comparing to get the legend.
################################################################

# Step 1: Title & Background for the Radar Chart
averagedMean<-signif(mean(df$sum)/5,3)
theTitle<-paste("SCAYL RESULTS\n",df1Name," \nOverall: ",averagedMean)
par(bg = " light grey")
# If comparing also run this
theTitle<-"SCAYL RESULTS"


################################################################
# Step 2: Radar Chart
# Check for comment about commenting out a line for comparing
radarchart(axistype=1, # The axis are included
           seg= 5, # The number of segments
           pcol = c(rgb(0.6,0.5,0.9,0.9),rgb(0.3,0.5,0.9,0.9),rgb(0.3,0.7,0.9,0.9)), # The colors of the connected lines

           # COMMENT OUT THE LINE BELOW IF COMPARING
           pfcol=rgb(0.6,0.5,0.9,0.3),
           ########################################

           plwd= 4, # The thickness of the  connected lines
           plty = 1,
           cglty=1, # The chart line type
           cglwd=0.8, # The chart line thickness
           cglcol=rgb(0.5,0.5,0.5), # The chart line color
           axislabcol = 'white', # The color of the axis
           caxislabels=seq(0,1,0.2),# The intervals of the axis
           title= theTitle, #The title -- set earlier
           vlcex=0.8, # The labels
           data)


################################################################
# Step 3: Legend
# If comparing also run this#
legend(x=1.5, y=1, legend = rownames(data[-c(1,2),]), bty = "n", pch=15 ,
       col=c(rgb(0.6,0.5,0.9,0.9),rgb(0.3,0.5,0.9,0.9),rgb(0.3,0.7,0.9,0.9)),
       cex=1.2, pt.cex=3)
################################################################

