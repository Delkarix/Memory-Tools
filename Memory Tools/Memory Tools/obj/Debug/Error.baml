   M S B A M L   `   `   `  ����G  CMemory Tools, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null+clr-namespace:Memory_ToolsMemory_Tools  5   	       Memory_Tools.Error   5   	   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   ,localclr-namespace:Memory_Tools     5   	   -   5          J� Opacity$  0Q�5   	    � Title$ Error��5	   	   $��167.249��6   $��327.549��6(   ���	#FF5A5A5A � WindowStyle$
 None=�6O    � AllowsTransparency .  � Triggers 5      :� 5   
    :� RoutedEvent$ Window.Loaded��6   .[�5      �� .��5      �� .��5      W�  g� Duration$ 
00:00:0.25D�6&    �� TargetProperty$ Opacity�6<   	 W� To$ 1X�6`   5      5      5      .��5      � .+�5   
   �� -   5        	 ��Name$	 OK��5      $��OK��6   $
��Left=�6*   $��130,137,0,0q�6E   $	��Top=�6Z   $��75��6r   6}   � 5   
   -   5        $
��Left=�5      $��35��6*   $	��Top=�66   $	��328��6N   .+�5      �� ���	#FF5A5A5A$
��Left=�6)   $��35��6D   ���	#FF5A5A5A$	��Top=�6c   $	��328��6{   �� 5      $
��Left=�6   $��	10,10,0,0q�63   $
��Wrap=�6F   $��ERROR��6Z   $	��Top=�6g   
���  ��$��16(�6�   �� 5      -   5        
 ��Name$
 CloseButton��5      $��x��6)   $
��Left=�65   $��298,-5,0,-1q�6P   $	��Top=�6e   
���   �$��32(�6�   $��41��6�   $��OCR A Extended)�6�    � ToolTip 5      _� 5      .��5      �� $��Close��6$   5       5!      :� 5"      $ Label.MouseEnter��6#   .[�5#      �� .��5$      �� .��5%   "   �� 	 �� To$	 RedX�61   $0 *(Label.Foreground).(SolidColorBrush.Color)�5&   %   $ 0:0:0.25D�5'   %   5(      5)      5*      :� 5,      $ Label.MouseLeave��6#   .[�5-      �� .��5.      �� .��5/   "   �� $ BlackX�61   $0 *(Label.Foreground).(SolidColorBrush.Color)�50   %   $ 0:0:0.25D�51   %   52      53      54      56      �� 57      -   5        $
 MinimizeButton��57      $��__��6,   $
��Left=�69   $��269,-5,0,-16q�6T   $	��Top=�6j   $��32(�6�   $��56��6�   $��OCR A Extended)�6�    58      _� 59      .��5:      �� $��Minimize��6$   5;       5>      :� 5?      $ Label.MouseEnter��6#   .[�5@      �� .��5A      �� .��5B   "   �� $ YellowX�61   $0 *(Label.Foreground).(SolidColorBrush.Color)�5C   %   $ 0:0:0.25D�5D   %   5E      5F      5G      :� 5I      $ Label.MouseLeave��6#   .[�5J      �� .��5K      �� .��5L   "   �� $ BlackX�61   $0 *(Label.Foreground).(SolidColorBrush.Color)�5M   %   $ 0:0:0.25D�5N   %   5O      5P      5Q      5S      5T      �� 5U   
   -   5         ��Name$ ErrorMsg��5U      $
��Left=�6&   $��	10,40,0,0q�6A   $
��Wrap=�6T   $	��Top=�6h   
�������$	��308��6�   $��92��6�   5W      5X      