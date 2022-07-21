# MSU REU 2022
# Gianforte School of Computing, Montana State University
# Created By: Cynthia Rosas
# Creating a Bar Chart for Scayl Results
################################################################
###---Library Used for the Bar Chart---###
library(ggplot2)
################################################################
###---Choose your file---###
ogData<-read.csv(file=file.choose())
################################################################
###---Creates the categories for the new data frame---###
category <- c(rep("Network Configuration", 3), 
              rep("Remote Access", 3), 
              rep("Information Sensitivity", 3), 
              rep("Command Line Permissions", 3),
              rep("File Permissions", 3))
severity <- rep(c("1. High", "2. Medium", "3. Low"), 5)
################################################################
###---Categorizes the CVE's in sections---###
firstMark <-0.333 
secondMark <-0.666
count <- c(sum(ogData$network>secondMark), sum(ogData$network>=firstMark&ogData$network<=secondMark), sum(ogData$network<firstMark),
           sum(ogData$remote>secondMark), sum(ogData$remote>=firstMark&ogData$remote<=secondMark), sum(ogData$remote<firstMark), 
           sum(ogData$information>secondMark), sum(ogData$information>=firstMark&ogData$information<=secondMark), sum(ogData$information<firstMark), 
           sum(ogData$permissions>secondMark), sum(ogData$permissions>=firstMark&ogData$permissions<=secondMark), sum(ogData$permissions<firstMark), 
           sum(ogData$files>secondMark), sum(ogData$files>=firstMark&ogData$files<=secondMark), sum(ogData$files<firstMark))

dataframe <- data.frame(category, severity, count)
################################################################
###---Stacked Bar Graph---###
title<- paste("Scayl Results\n",(sum(ogData$network>0.5)+sum(ogData$network<=0.5)),"CVEs")

ggplot(dataframe, 
       aes(fill = severity, y = count, x = category))+
  geom_bar(position = "stack", stat = "identity")+
  ggtitle(title)+
  theme(plot.title = element_text(hjust = 0.5))+
  scale_fill_manual(values = c("#6A51A3", "#9E9AC8", "#DADAEB"))
################################################################
