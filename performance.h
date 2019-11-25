#ifndef PERFORMANCE_H
#define PERFORMANCE_H

#include <ctime>
#include <string>
#include <iostream>
#include <stack>
#include <utility>

using namespace std;

void time_log(string tag) {
    static stack<pair<string, chrono::high_resolution_clock::time_point>> sentinel;
    
    if (sentinel.empty() || sentinel.top().first != tag) {
        auto start = chrono::high_resolution_clock::now();
        sentinel.push(make_pair(tag, start));
    }

    else {
        auto start = sentinel.top().second;
        auto end = chrono::high_resolution_clock::now();
        cout << "[Time] " << tag << ": " 
            << chrono::duration_cast<std::chrono::milliseconds>(end-start).count() * 1.0 
            << " ms" << std::endl;
        sentinel.pop();
    }
}

#endif // PERFORMANCE_H

