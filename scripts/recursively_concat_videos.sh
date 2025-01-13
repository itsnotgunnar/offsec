#!/bin/bash
# Recursively concatenates mp4 videos in directory

# Loop through directories starting with "Lesson" in the current directory                                             
for dir in Lesson*/; do                                                                                                
  # Check if it's a directory                                                                                          
  if [ -d "$dir" ]; then                                                                                               
    # Change into the directory                                                                                        
    cd "$dir" || continue                                                                                              
                                                                                                                       
    # Find .webm files, sort them, and save to videos.txt                                                              
    find . -name "*.mp4" | sort -V > videos.txt                                                                       
    sleep 1                                                                                                            
                                                                                                                       
    # Modify videos.txt to the required format                                                                         
    sed "s/\(.*\)$/file '\1'/" videos.txt > tmp.txt
    sleep 1                                                                                                            
                                                                                                                       
    # Replace videos.txt with the modified version                                                                     
    mv tmp.txt videos.txt                                                                                              
    sleep 1                                                                                                            
                                                                                                                       
    # Get the directory name without trailing slash                                                                    
    dir_name=$(basename "$dir")                                                                                        
                                                                                                                       
    # Concatenate videos using ffmpeg                                                                                  
    ffmpeg -f concat -safe 0 -i videos.txt -c copy "${dir_name}.mp4"                                                   
                                                                                                                       
    # Change back to the parent directory                                                                              
    cd ..                                                                                                              
  fi                                                                                                                   
done