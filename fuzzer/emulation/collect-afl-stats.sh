#! /bin/bash

# Read file ioctmcmds.txt and for each cmd read file output-<cmd>/fuzzer_stats

IOCTLCMDS_PATH="ioctlcmds.txt"

# source: https://unix.stackexchange.com/questions/27013/displaying-seconds-as-days-hours-mins-seconds/338844
function displaytime {
  local T=$1
  local D=$((T/60/60/24))
  local H=$((T/60/60%24))
  local M=$((T/60%60))
  local S=$((T%60))
  (( $D > 0 )) && printf '%d days ' $D
  (( $H > 0 )) && printf '%d hours ' $H
  (( $M > 0 )) && printf '%d minutes' $M
  (( $D == 0 && $H == 0 && $M == 0 )) && printf 'less than a minute'
  #(( $D > 0 || $H > 0 || $M > 0 )) && printf 'and '
  #printf '%d seconds' $S
}


echo "#cmd, dur_sec, dur_pretty, total_execs, total_paths, unique_crashes, uniques_hangs, avg_speed"
while read cmd; do
  # In the current version, we have one cmd per line, but the old one has
  # val_1: <cmd>
  # We need to deal with this old format too

  #echo " --- $cmd"
  #ls "output-$cmd"/fuzzer_stats

  statsfile="output-$cmd/fuzzer_stats"
  plotfile="output-$cmd/plot_data"
  if [[ -f "$statsfile" ]]; then
    start_time=$(grep start_time $statsfile | cut -f2 -d: | tr -d ' ')
    end_time=$(grep last_update $statsfile | cut -f2 -d: | tr -d ' ')
    total_execs=$(grep execs_done $statsfile | cut -f2 -d: | tr -d ' ')
    total_paths=$(grep paths_total $statsfile | cut -f2 -d: | tr -d ' ')
    uniq_crashes=$(grep unique_crashes $statsfile | cut -f2 -d: | tr -d ' ')
    uniq_hangs=$(grep unique_hangs $statsfile | cut -f2 -d: | tr -d ' ')
    duration_secs=$(($end_time-$start_time))
    duration_pretty=$(displaytime $duration_secs)
    
    # Collect average exec speed from the plot_data file
    RSCRIPT="avg_rate.r"
    echo "data <- read.csv(file=\"output-$cmd/plot_data\", sep=\",\")" > $RSCRIPT
    echo "rates <- data[,11]" >> $RSCRIPT
    echo "avgrate <- sum(rates)/(length(rates)-1)" >> $RSCRIPT
    echo "cat(avgrate)" >> $RSCRIPT
    avg_rate=$(R --slave --no-save < avg_rate.r)
    echo "$cmd, $duration_secs, $duration_pretty, $total_execs, $total_paths, $uniq_crashes, $uniq_hangs, $avg_rate"
  else
    total_execs=1
    total_paths=1
    uniq_crashes=1
    uniq_hangs=0
    duration_secs=0
    duration_pretty="crashed right away"
    avg_rate=0
    echo "$cmd, $duration_secs, $duration_pretty, $total_execs, $total_paths, $uniq_crashes, $uniq_hangs, $avg_rate"
  fi
    
  #break

  #echo "     start=$start_time"
  #echo "     end=$end_time"
  #displaytime $duration_secs

done <  <(sed 's/val_1: //g' $IOCTLCMDS_PATH) # we need to account for the old "val_1: <cmd>" format
