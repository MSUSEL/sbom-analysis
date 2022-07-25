# MSU REU 2022
# Gianforte School of Computing, Montana State University
# Created By: Cynthia Rosas
# Creating a Bar Chart for Scayl Results
################################################################
###---Library Used for the Bar Chart---###
library(ggplot2)
################################################################
################################################################
################################################################
################################################################
#SECTION 1: The first step is to select the file you want to 
#run and the name of the data. Following that is running a few 
#lines to organize the data in categories
################################################################
################################################################
################################################################
################################################################
###---Step 1:Choose your file---###
ogData<-read.csv(file=file.choose())
dfNAME<-"Dataframe"
################################################################
###---Step 2:Creates the categories for the new data frame---###
category <- c(rep("Network Configuration", 3), 
              rep("File Permissions", 3),
              rep("Remote Access", 3), 
              rep("Information Sensitivity", 3), 
              rep("Command Line Permissions", 3))
severity <- rep(c("1. High", "2. Medium", "3. Low"), 5)
################################################################
################################################################
################################################################
################################################################
#SECTION 2: The default dividers are at one third and two thirds.
#This can be changed below to preference of what you would like
#to consider high or low.
################################################################
################################################################
################################################################
################################################################
###---Categorizes the CVE's in sections---###
firstMark <-0.333 
secondMark <-0.666
count <- c(sum(ogData$network>secondMark), sum(ogData$network>=firstMark&ogData$network<=secondMark), sum(ogData$network<firstMark),
           sum(ogData$files>secondMark), sum(ogData$files>=firstMark&ogData$files<=secondMark), sum(ogData$files<firstMark)
           sum(ogData$remote>secondMark), sum(ogData$remote>=firstMark&ogData$remote<=secondMark), sum(ogData$remote<firstMark), 
           sum(ogData$information>secondMark), sum(ogData$information>=firstMark&ogData$information<=secondMark), sum(ogData$information<firstMark), 
           sum(ogData$permissions>secondMark), sum(ogData$permissions>=firstMark&ogData$permissions<=secondMark), sum(ogData$permissions<firstMark))
################################################################
################################################################
################################################################
################################################################
#SECTION 3: This is the actual stacked bar graph. The first line
#runs the title and the next line runs the graph.
################################################################
################################################################
################################################################
################################################################
###---Stacked Bar Graph---###
title<- paste("Scayl Results\n",dfNAME,"\n",(sum(ogData$network>0.5)+sum(ogData$network<=0.5)),"CVEs")

ggplot(dataframe, 
       aes(fill = severity, y = count, x = category))+
  geom_bar(position = "stack", stat = "identity")+
  ggtitle(title)+
  theme(plot.title = element_text(hjust = 0.5))+
  scale_fill_manual(values = c("#6A51A3", "#9E9AC8", "#DADAEB"))
################################################################
