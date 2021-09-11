# pair programmed by Mary+Josh

rows = [
  # insert output of problem_specific.go#ReUseCTRSeed
]

keys = []

def build_helper_row(size)
  out = ""
  size.times do |i|
    out += "%3d" % i
    out += " "
  end
  out
end

def build_raw_row(row)
  row.map do |d|
    '%3d' % d
  end.join(' ')
end

def build_output_row(row, keys)
  keys.map.with_index do |k, i|
    if k.nil? || row[i].nil?
      "   "
    else 
      target = k ^ row[i]
      if target >= 32 && target <= 127
        " #{target.chr} "
      else
        "ERR"
      end
    end
  end.join(' ')
end

greatest_length = rows.map(&:length).max
index_row = build_helper_row(greatest_length)

puts index_row
rows.each do |row|
  puts build_raw_row(row)
end
puts "---"

while true do
  puts "Which column do you want to adjust?"
  target_col = gets.chomp.to_i
  puts "What encrypted value?"
  encrypted_val = gets.chomp.to_i
  puts "What character does it equal?"
  candidate_val = gets.chomp

  keys[target_col] = encrypted_val ^ candidate_val.ord

  # clear screen
  puts "\e[H\e[2J"

  puts index_row
  rows.each do |row|
    puts build_raw_row(row)
    puts build_output_row(row, keys)
  end
end
