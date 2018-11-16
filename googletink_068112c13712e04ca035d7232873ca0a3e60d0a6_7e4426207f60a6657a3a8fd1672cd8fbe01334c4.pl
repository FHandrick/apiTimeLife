/* facts */

/* metohod(1...  - Move Method */
/* metohod(2...  - Rename Method */
/* metohod(3...  - Remove Method */
/* metohod(4...  - Push Down Method */
/* metohod(5...  - Inline Method */
/* metohod(6...  - Change in Parameter List Method */
/* metohod(7...  - Change in Exception LIst Method*/
/* metohod(8...  - Change in Return TYpe Method */
/* metohod(9...  - Lost Visibility Method */
/* metohod(10...  - Add Final Modifier */
/* metohod(11...  - Remove Static Modifier */



method_move_count(Y):-findall(X,method(1,A,B,C),L),length(L,Y).
method_rename_count(Y):-findall(X,method(2,A,B,C),L),length(L,Y).
method_remove_count(Y):-findall(X,method(3,A,B),L),length(L,Y).
method_inline_count(Y):-findall(X,method(5,A,B),L),length(L,Y).
method_change_exception_list_count(Y):-findall(X,method(7,A,B),L),length(L,Y).
method_change_return_type_count(Y):-findall(X,method(8,A,B),L),length(L,Y).
method_lost_visibility_count(Y):-findall(X,method(9,A,B),L),length(L,Y).
method_add_modifier_final_count(Y):-findall(X,method(10,A,B),L),length(L,Y).
method_remove_modifier_static_count(Y):-findall(X,method(11,A,B),L),length(L,Y).


all_method_change(A,B,C,D,E,F,G,H,I):-method_move_count(A),method_rename_count(B),method_remove_count(C),
method_inline_count(D),method_change_exception_list_count(E),method_change_return_type_count(F),method_lost_visibility_count(G),
method_add_modifier_final_count(H),method_remove_modifier_static_count(I).
